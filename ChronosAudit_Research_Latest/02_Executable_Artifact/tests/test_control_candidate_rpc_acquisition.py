from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError

import pytest
import yaml

from chronosaudit_stage2.public_acquisition import control_candidate_rpc_acquisition as rpc_acquisition

from chronosaudit_stage2.public_acquisition.control_candidate_rpc_acquisition import (
    _round_robin_by_case,
    execute_control_candidate_rpc_acquisition,
    prepare_control_candidate_rpc_acquisition,
)
from chronosaudit_stage2.public_acquisition.providers import endpoint_id


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(tmp_path: Path) -> dict[str, Path]:
    providers = []
    bindings = []
    for chain in ("ethereum", "bsc", "base", "arbitrum"):
        for suffix in ("a", "b"):
            endpoint = f"https://{chain}-{suffix}.example/rpc"
            provider_id = f"{chain}-{suffix}"
            family = f"family-{suffix}"
            providers.append(
                {
                    "provider_id": provider_id,
                    "chain": chain,
                    "endpoint": endpoint,
                    "operator_family": family,
                    "discovery_source": f"https://docs.example/{provider_id}",
                    "tracking_enabled": True,
                    "operator_evidence_url": f"https://docs.example/{provider_id}",
                    "operator_evidence_sha256": suffix * 64,
                    "operator_verified": True,
                }
            )
            bindings.append(
                {
                    "chain": chain,
                    "provider_id": provider_id,
                    "operator_family": family,
                    "public_endpoint_identity_id": endpoint_id(endpoint),
                }
            )
    registry = tmp_path / "providers.yaml"
    registry.write_text(yaml.safe_dump({"version": "test", "providers": providers}), encoding="utf-8")
    queue = tmp_path / "queue.csv"
    fields = [
        "case_name",
        "chain",
        "positive_prediction_cutoff_time",
        "control_address",
        "creation_tx_hash",
        "deployment_block",
        "reserve_assignment_sha256",
    ]
    with queue.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "case_name": "case-one",
                "chain": "ethereum",
                "positive_prediction_cutoff_time": "2021-01-02T00:00:00Z",
                "control_address": "0x" + "ab" * 20,
                "creation_tx_hash": "0x" + "cd" * 32,
                "deployment_block": "100",
                "reserve_assignment_sha256": "1" * 64,
            }
        )
    activation_request = tmp_path / "activation-request.json"
    activation_request_body = {
        "provider_registry_sha256": _file_sha(registry),
        "queue_sha256": _file_sha(queue),
        "rpc_methods": ["eth_chainId", "eth_getTransactionReceipt", "eth_getBlockByHash"],
    }
    activation_request_payload = dict(activation_request_body)
    activation_request_payload["request_sha256"] = hashlib.sha256(
        json.dumps(
            activation_request_body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    activation_request.write_text(
        json.dumps(activation_request_payload, sort_keys=True), encoding="utf-8"
    )
    activation = tmp_path / "activation.json"
    activation.write_text(
        json.dumps(
            {
                "schema_version": "chronosaudit.control_candidate_rpc_activation_verification.v1",
                "decision": "RPC_ACTIVATION_VERIFIED",
                "rpc_authorized": True,
                "acquisition_authorized": False,
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
                "hash_chained_no_repeat_ledger_required": True,
                "queue_sha256": _file_sha(queue),
                "queue_row_count": 1,
                "provider_registry_sha256": _file_sha(registry),
                "provider_bindings": bindings,
                "rpc_methods": ["eth_chainId", "eth_getTransactionReceipt", "eth_getBlockByHash"],
                "request_sha256": activation_request_payload["request_sha256"],
                "maximum_rpc_requests": 12,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return {"activation": activation, "activation_request": activation_request, "queue": queue, "registry": registry, "output": tmp_path / "run"}


def test_execute_is_consensus_bound_and_resume_does_not_repeat_complete_work(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    calls: list[tuple[str, str]] = []
    chain_ids = {"ethereum": "0x1", "bsc": "0x38", "base": "0x2105", "arbitrum": "0xa4b1"}

    def transport(endpoint: str, method: str, params: list[object]):
        calls.append((endpoint, method))
        chain = endpoint.removeprefix("https://").split("-", 1)[0]
        if method == "eth_chainId":
            return {"jsonrpc": "2.0", "id": 1, "result": chain_ids[chain]}
        if method == "eth_getTransactionReceipt":
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "transactionHash": "0x" + "cd" * 32,
                    "blockNumber": "0x64",
                    "blockHash": "0x" + "ef" * 32,
                    "contractAddress": "0x" + "ab" * 20,
                    "status": "0x1",
                },
            }
        assert method == "eth_getBlockByHash"
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"number": "0x64", "hash": "0x" + "ef" * 32, "timestamp": "0x5fee6600"},
        }

    prepared = prepare_control_candidate_rpc_acquisition(
        activation_path=paths["activation"],
        activation_request_path=paths["activation_request"],
        queue_path=paths["queue"],
        provider_registry_path=paths["registry"],
        output_root=paths["output"],
    )
    first = execute_control_candidate_rpc_acquisition(prepared, transport=transport)

    assert first["completed_count"] == 1
    assert first["completed_case_count"] == 1
    assert first["rpc_classification_complete_count"] == 1
    assert first["trace_required_count"] == 0
    assert first["ledger_status_counts"] == {"COMPLETE": 1}
    assert first["remaining_count"] == 0
    assert first["new_partial_count"] == 0
    assert len(calls) == 6
    result = json.loads(next((paths["output"] / "candidates").glob("*.json")).read_text())
    assert result["creation_type"] == "TOP_LEVEL_CREATE_RECEIPT_PROVEN"
    assert result["provider_consensus"] is True
    assert result["selection_authorized"] is False

    calls.clear()
    second = execute_control_candidate_rpc_acquisition(prepared, transport=transport)
    assert second["completed_count"] == 1
    assert second["new_complete_count"] == 0
    assert calls == []


def test_pending_candidates_are_round_robin_by_case_without_changing_row_order_within_case() -> None:
    rows = [
        {"case_name": "a", "slot": "1"},
        {"case_name": "a", "slot": "2"},
        {"case_name": "a", "slot": "3"},
        {"case_name": "b", "slot": "1"},
        {"case_name": "b", "slot": "2"},
        {"case_name": "c", "slot": "1"},
    ]

    ordered = _round_robin_by_case(rows)

    assert [(row["case_name"], row["slot"]) for row in ordered] == [
        ("a", "1"),
        ("b", "1"),
        ("c", "1"),
        ("a", "2"),
        ("b", "2"),
        ("a", "3"),
    ]


def test_prepare_resolves_managed_endpoint_only_at_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _inputs(tmp_path)
    registry = yaml.safe_load(paths["registry"].read_text(encoding="utf-8"))
    record = next(
        row
        for row in registry["providers"]
        if row["provider_id"] == "ethereum-a"
    )
    record["endpoint"] = "https://ethereum-a.example/"
    record["endpoint_env"] = "CHRONOS_ETHEREUM_A_URL"
    paths["registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    runtime_url = "https://ethereum-a.example/private-runtime-token"
    monkeypatch.setenv("CHRONOS_ETHEREUM_A_URL", runtime_url)

    request = json.loads(paths["activation_request"].read_text(encoding="utf-8"))
    request["provider_registry_sha256"] = _file_sha(paths["registry"])
    request["request_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in request.items() if key != "request_sha256"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    paths["activation_request"].write_text(
        json.dumps(request, sort_keys=True), encoding="utf-8"
    )
    activation = json.loads(paths["activation"].read_text(encoding="utf-8"))
    activation["request_sha256"] = request["request_sha256"]
    activation["provider_registry_sha256"] = _file_sha(paths["registry"])
    for binding in activation["provider_bindings"]:
        if binding["provider_id"] == "ethereum-a":
            binding["public_endpoint_identity_id"] = endpoint_id(
                "https://ethereum-a.example/"
            )
    paths["activation"].write_text(
        json.dumps(activation, sort_keys=True), encoding="utf-8"
    )

    prepared = prepare_control_candidate_rpc_acquisition(
        activation_path=paths["activation"],
        activation_request_path=paths["activation_request"],
        queue_path=paths["queue"],
        provider_registry_path=paths["registry"],
        output_root=paths["output"],
    )

    selected = {
        provider.provider_id: provider
        for provider in prepared["providers"]["ethereum"]
    }
    assert selected["ethereum-a"].endpoint == runtime_url
    assert selected["ethereum-a"].public_endpoint_id == endpoint_id(
        "https://ethereum-a.example/"
    )


def test_prepare_resolves_only_exact_queue_chain_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _inputs(tmp_path)
    rows = list(csv.DictReader(paths["queue"].open(encoding="utf-8")))
    rows[0]["chain"] = "bsc"
    with paths["queue"].open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    registry = yaml.safe_load(paths["registry"].read_text(encoding="utf-8"))
    ethereum = next(
        row for row in registry["providers"] if row["provider_id"] == "ethereum-a"
    )
    ethereum["endpoint"] = "https://ethereum-a.example/"
    ethereum["endpoint_env"] = "CHRONOS_UNSET_UNRELATED_ETHEREUM_URL"
    paths["registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    request = json.loads(paths["activation_request"].read_text(encoding="utf-8"))
    request["provider_registry_sha256"] = _file_sha(paths["registry"])
    request["queue_sha256"] = _file_sha(paths["queue"])
    request["request_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in request.items() if key != "request_sha256"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    paths["activation_request"].write_text(json.dumps(request), encoding="utf-8")
    activation = json.loads(paths["activation"].read_text(encoding="utf-8"))
    activation["queue_sha256"] = _file_sha(paths["queue"])
    activation["provider_registry_sha256"] = _file_sha(paths["registry"])
    activation["request_sha256"] = request["request_sha256"]
    activation["provider_bindings"] = [
        binding for binding in activation["provider_bindings"] if binding["chain"] == "bsc"
    ]
    paths["activation"].write_text(json.dumps(activation), encoding="utf-8")
    monkeypatch.delenv("CHRONOS_UNSET_UNRELATED_ETHEREUM_URL", raising=False)

    prepared = prepare_control_candidate_rpc_acquisition(
        activation_path=paths["activation"],
        activation_request_path=paths["activation_request"],
        queue_path=paths["queue"],
        provider_registry_path=paths["registry"],
        output_root=paths["output"],
    )

    assert set(prepared["providers"]) == {"bsc"}


def test_default_transport_does_not_hide_rate_limit_retries(monkeypatch) -> None:
    attempts = 0

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self) -> bytes:
            return b'{"jsonrpc":"2.0","id":1,"result":"0x1"}'

    def fake_urlopen(_request, timeout):
        nonlocal attempts
        assert timeout == 30
        attempts += 1
        if attempts == 1:
            raise HTTPError(
                "https://ethereum.example/rpc", 429, "Too Many Requests",
                {"Retry-After": "0"}, None,
            )
        return Response()

    monkeypatch.setattr(rpc_acquisition, "urlopen", fake_urlopen)

    with pytest.raises(HTTPError) as error:
        rpc_acquisition.default_transport(
            "https://ethereum.example/rpc", "eth_chainId", []
        )

    assert error.value.code == 429
    assert attempts == 1


def test_resume_marks_interrupted_request_scope_partial_without_replay(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    chain_ids = {"ethereum": "0x1", "bsc": "0x38", "base": "0x2105", "arbitrum": "0xa4b1"}
    candidate_calls = 0

    def interrupted(endpoint: str, method: str, params: list[object]):
        nonlocal candidate_calls
        chain = endpoint.removeprefix("https://").split("-", 1)[0]
        if method == "eth_chainId":
            return {"jsonrpc": "2.0", "id": 1, "result": chain_ids[chain]}
        candidate_calls += 1
        raise KeyboardInterrupt("simulated hard interruption")

    prepared = prepare_control_candidate_rpc_acquisition(
        activation_path=paths["activation"],
        activation_request_path=paths["activation_request"],
        queue_path=paths["queue"],
        provider_registry_path=paths["registry"],
        output_root=paths["output"],
    )
    with pytest.raises(KeyboardInterrupt):
        execute_control_candidate_rpc_acquisition(prepared, transport=interrupted)
    assert candidate_calls == 1

    replayed_candidate_calls = 0

    def must_not_replay(_endpoint: str, method: str, _params: list[object]):
        nonlocal replayed_candidate_calls
        if method != "eth_chainId":
            replayed_candidate_calls += 1
        raise AssertionError("interrupted candidate scope must not replay")

    summary = execute_control_candidate_rpc_acquisition(
        prepared, transport=must_not_replay
    )

    assert replayed_candidate_calls == 0
    assert summary["ledger_status_counts"] == {"PARTIAL": 1}
    assert summary["retry_required_count"] == 1
    assert summary["remaining_count"] == 1


def test_signed_request_ceiling_is_enforced_before_candidate_scope(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    activation = json.loads(paths["activation"].read_text(encoding="utf-8"))
    activation["maximum_rpc_requests"] = 5
    paths["activation"].write_text(json.dumps(activation), encoding="utf-8")
    calls: list[tuple[str, str]] = []
    chain_ids = {"ethereum": "0x1", "bsc": "0x38", "base": "0x2105", "arbitrum": "0xa4b1"}

    def transport(endpoint: str, method: str, _params: list[object]):
        calls.append((endpoint, method))
        chain = endpoint.removeprefix("https://").split("-", 1)[0]
        assert method == "eth_chainId"
        return {"jsonrpc": "2.0", "id": 1, "result": chain_ids[chain]}

    prepared = prepare_control_candidate_rpc_acquisition(
        activation_path=paths["activation"],
        activation_request_path=paths["activation_request"],
        queue_path=paths["queue"],
        provider_registry_path=paths["registry"],
        output_root=paths["output"],
    )
    summary = execute_control_candidate_rpc_acquisition(prepared, transport=transport)

    assert len(calls) == 2
    assert summary["completed_count"] == 0
    assert summary["remaining_count"] == 1
    assert summary["request_count"] == 2
    assert summary["remaining_request_budget"] == 3
    assert summary["request_budget_exhausted"] is True
    request_events = [
        json.loads(line)
        for line in (paths["output"] / "request-events.jsonl").read_text().splitlines()
    ]
    assert len(request_events) == 2
    assert request_events[-1]["request_sequence"] == 2
    assert request_events[-1]["event_sha256"] == summary["request_ledger_terminal_hash"]
    assert all("example/rpc" not in json.dumps(event) for event in request_events)


def test_partial_scope_requires_new_activation_instead_of_replaying(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    calls: list[tuple[str, str]] = []
    chain_ids = {"ethereum": "0x1", "bsc": "0x38", "base": "0x2105", "arbitrum": "0xa4b1"}

    def transport(endpoint: str, method: str, _params: list[object]):
        calls.append((endpoint, method))
        chain = endpoint.removeprefix("https://").split("-", 1)[0]
        if method == "eth_chainId":
            return {"jsonrpc": "2.0", "id": 1, "result": chain_ids[chain]}
        raise HTTPError(endpoint, 429, "Too Many Requests", {}, None)

    prepared = prepare_control_candidate_rpc_acquisition(
        activation_path=paths["activation"],
        activation_request_path=paths["activation_request"],
        queue_path=paths["queue"],
        provider_registry_path=paths["registry"],
        output_root=paths["output"],
    )
    first = execute_control_candidate_rpc_acquisition(prepared, transport=transport)

    assert first["completed_count"] == 0
    assert first["new_partial_count"] == 1
    assert first["retry_required_count"] == 1
    assert first["request_count"] == 3
    request_events = [
        json.loads(line)
        for line in (paths["output"] / "request-events.jsonl").read_text().splitlines()
    ]
    assert request_events[-1]["disposition"] == "TRANSPORT_ERROR"
    assert request_events[-1]["error_code"] == "http_429"
    assert "https://" not in json.dumps(request_events[-1])

    calls.clear()
    second = execute_control_candidate_rpc_acquisition(prepared, transport=transport)
    assert calls == []
    assert second["new_partial_count"] == 0
    assert second["retry_required_count"] == 1
    assert second["request_count"] == 3


def test_deterministic_address_mismatch_is_terminally_rejected_on_resume(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    calls: list[str] = []
    chain_ids = {"ethereum": "0x1", "bsc": "0x38", "base": "0x2105", "arbitrum": "0xa4b1"}

    def transport(endpoint: str, method: str, _params: list[object]):
        calls.append(method)
        chain = endpoint.removeprefix("https://").split("-", 1)[0]
        if method == "eth_chainId":
            return {"jsonrpc": "2.0", "id": 1, "result": chain_ids[chain]}
        if method == "eth_getTransactionReceipt":
            return {
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "transactionHash": "0x" + "cd" * 32,
                    "blockNumber": "0x64",
                    "blockHash": "0x" + "ef" * 32,
                    "contractAddress": "0x" + "11" * 20,
                    "status": "0x1",
                },
            }
        return {
            "jsonrpc": "2.0", "id": 1,
            "result": {"number": "0x64", "hash": "0x" + "ef" * 32, "timestamp": "0x5fee6600"},
        }

    prepared = prepare_control_candidate_rpc_acquisition(
        activation_path=paths["activation"], activation_request_path=paths["activation_request"],
        queue_path=paths["queue"], provider_registry_path=paths["registry"],
        output_root=paths["output"],
    )
    first = execute_control_candidate_rpc_acquisition(prepared, transport=transport)
    assert first["completed_count"] == 0
    assert first["terminal_rejected_count"] == 1
    assert first["remaining_count"] == 0

    calls.clear()
    second = execute_control_candidate_rpc_acquisition(prepared, transport=transport)
    assert second["new_terminal_rejected_count"] == 0
    assert calls == []
