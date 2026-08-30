from __future__ import annotations

import json
import hashlib
from pathlib import Path

from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.public_acquisition.control_base_state_retry_targets import (
    build_base_state_retry_targets,
)
from chronosaudit_stage2.public_acquisition.control_cutoff_state_acquisition import (
    execute_control_cutoff_state_acquisition,
)

from test_control_cutoff_state_acquisition import _batch_inputs
from test_control_cutoff_state_acquisition import IMPLEMENTATION, _canonical_sha


def test_retry_subset_requires_failed_row_and_hash_chained_provider_error(
    tmp_path: Path,
):
    targets_path, activation, provider_map = _batch_inputs(tmp_path)
    targets = json.loads(targets_path.read_text(encoding="utf-8"))
    targets["schema_version"] = "stage2_control_base_state_targets.v1"
    targets["decision"] = "BASE_STATE_TARGETS_FROZEN_AWAITING_EXACT_ACTIVATION"
    targets["complete"] = True
    targets["counter_authority"] = False
    targets["rpc_authorized"] = False
    targets["derived_address_reads_authorized"] = False
    targets["selection_authorized"] = False
    targets["stage_promotion_authorized"] = False
    targets["recovery3_mutation_authorized"] = False
    targets["targets"][0]["cutoff_timestamp"] = "1970-01-01T00:01:40Z"
    targets["targets"][0]["cutoff_timestamp_unix"] = 100
    targets["targets"][0]["calls"] = [
        call for call in targets["targets"][0]["calls"]
        if not (
            call["method"] == "eth_getCode"
            and str(call["params"][0]).lower() == IMPLEMENTATION
        )
    ]
    targets["target_count"] = 1
    targets["call_count"] = len(targets["targets"][0]["calls"])
    targets["targets_sha256"] = _canonical_sha(targets)
    targets_path.write_text(json.dumps(targets), encoding="utf-8")
    activation["schema_version"] = "stage2_control_base_state_activation_verification.v1"
    activation["decision"] = "BASE_STATE_RPC_ACTIVATION_VERIFIED"
    activation["derived_address_reads_authorized"] = False
    activation["base_state_targets_file_sha256"] = hashlib.sha256(
        targets_path.read_bytes()
    ).hexdigest()
    activation.pop("state_targets_sha256")
    activation["rpc_call_scopes"] = [
        {**scope, "target_type": "base_state"}
        for scope in activation["rpc_call_scopes"]
        if not (
            scope["method"] == "eth_getCode"
            and str(scope["params"][0]).lower() == IMPLEMENTATION
        )
    ]
    for scope in activation["rpc_call_scopes"]:
        material = {key: value for key, value in scope.items() if key != "call_scope_sha256"}
        scope["call_scope_sha256"] = _canonical_sha(material)
    activation["maximum_request_count"] = len(activation["rpc_call_scopes"])
    activation.pop("verification_sha256")
    activation["verification_sha256"] = _canonical_sha(activation)

    def transport(provider_id: str, method: str, params: list[object]):
        if provider_id == "provider-b" and method == "eth_getCode":
            return ProviderObservation(
                provider_id=provider_id,
                method=method,
                params=params,
                result=None,
                observed_at_unix=1,
                error="TimeoutError: read operation timed out",
                provider_family="family-b",
                observed_at_utc="2026-08-21T01:00:00Z",
            )
        return provider_map[provider_id].call(method, params)

    result = execute_control_cutoff_state_acquisition(
        activation=activation,
        state_targets_path=targets_path,
        output_root=tmp_path / "partial-run",
        transport=transport,
        now_utc="2026-08-21T01:00:00Z",
    )
    assert result["status"] == "PARTIAL_NON_AUTHORIZING"
    output = tmp_path / "retry-targets.json"
    retry = build_base_state_retry_targets(
        original_targets_path=targets_path,
        checkpoint_path=Path(result["checkpoint_path"]),
        output_path=output,
    )
    assert retry["target_count"] == 1
    assert retry["retry_reason"] == "HASH_CHAINED_PROVIDER_ERROR_ONLY"
    persisted = json.loads(output.read_text(encoding="utf-8"))
    assert persisted["targets"][0]["target_id"] == "state-1"
