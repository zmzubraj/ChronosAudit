from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_amendment import (
    ControlProviderIdentityLegacyAliasAmendmentError,
    build_legacy_alias_amendment_request,
    verify_legacy_alias_amendment_request,
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _self_hashed(payload: dict[str, object], key: str) -> dict[str, object]:
    result = dict(payload)
    result[key] = _canonical_sha(result)
    return result


def _inputs(tmp_path: Path) -> dict[str, Path]:
    executable = tmp_path / "02_Executable_Artifact"
    review_kit = executable / "docs" / "stage2_control_provider_identity_review_kit.md"
    review_kit.parent.mkdir(parents=True)
    review_kit.write_text("provider identity review\n", encoding="utf-8")

    historical = {
        "schema_version": "chronosaudit.control_provider_identity_legacy_alias_amendment_request.v1",
        "decision": "AWAITING_EXPLICIT_METHOD_APPROVAL",
        "request_sha256": "0" * 64,
    }
    historical_path = _write_json(
        executable
        / "reports/stage2_controls/2026-08-21/provider-identity-legacy-alias-amendment-request-v1/provider_identity_legacy_alias_amendment_request.json",
        historical,
    )

    targets = []
    for chain, suffix in (("base", "1"), ("bsc", "2"), ("ethereum", "3")):
        targets.append(
            {
                "target_id": f"trace-{'a' * 63}{suffix}",
                "case_id": f"case-{chain}",
                "chain": chain,
                "chain_address": f"{chain}:0x{'1' * 40}",
                "transaction_hash": f"0x{'2' * 64}",
                "block_number": 100,
                "block_hash": f"0x{'3' * 64}",
                "reserve_assignment_sha256": f"{'a' * 63}{suffix}",
                "reserve_record_sha256": "b" * 64,
                "reserve_record_file_sha256": "c" * 64,
            }
        )
    identities = _self_hashed(
        {
            "schema_version": "stage2_control_trace_target_identities.v1",
            "source_reconciliation_count": 1,
            "source_reconciliations": [],
            "target_count": 3,
            "chain_target_counts": {"base": 1, "bsc": 1, "ethereum": 1},
            "targets": targets,
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
        "target_identities_sha256",
    )
    identities_path = _write_json(
        executable
        / "processed/stage2_controls/2026-08-23/control-effective-trace-target-identities-v1/control_trace_target_identities.json",
        identities,
    )

    family_pairs = {
        "base": (("drpc-base", "drpc"), ("merkle-base", "merkle")),
        "bsc": (("nodereal-bsc", "nodereal"), ("merkle-bsc", "merkle")),
        "ethereum": (
            ("quicknode-ethereum", "quicknode"),
            ("merkle-ethereum", "merkle"),
        ),
    }
    chains = []
    for chain, pairs in family_pairs.items():
        providers = [
            {
                "provider_id": provider_id,
                "provider_family": family,
                "trace_method": "trace_transaction",
                "known_creation_recovered": True,
            }
            for provider_id, family in pairs
        ]
        chains.append(
            {
                "chain": chain,
                "complete": True,
                "providers": providers,
                "verified_operator_families": sorted(
                    provider["provider_family"] for provider in providers
                ),
            }
        )
    transport = _self_hashed(
        {
            "schema_version": "stage2_control_trace_state_capability.v1",
            "complete": True,
            "errors": [],
            "chain_count": 3,
            "chains": chains,
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
        "report_sha256",
    )
    transport_path = _write_json(
        executable
        / "reports/stage2_controls/2026-08-21/local-test-unverified-merkle-dual-provider-capability-v2/control_trace_state_capability.json",
        transport,
    )
    transport_verification = _self_hashed(
        {
            "schema_version": "stage2_control_trace_state_capability_verification.v1",
            "complete": True,
            "errors": [],
            "report_sha256": transport["report_sha256"],
            "report_file_sha256": _file_sha(transport_path),
            "provider_registry_verified": False,
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
        "verification_sha256",
    )
    transport_verification_path = _write_json(
        executable
        / "reports/stage2_controls/2026-08-21/local-test-unverified-merkle-dual-provider-capability-v2/control_trace_state_capability_verification.json",
        transport_verification,
    )

    trace_rows = []
    providers_by_chain = {
        row["chain"]: sorted(
            (
                {
                    "provider_id": provider["provider_id"],
                    "operator_family": provider["provider_family"],
                    "method": provider["trace_method"],
                }
                for provider in row["providers"]
            ),
            key=lambda provider: provider["provider_id"],
        )
        for row in chains
    }
    for identity in targets:
        row = dict(identity)
        row["calls"] = [
            {**provider, "params": [identity["transaction_hash"]]}
            for provider in providers_by_chain[identity["chain"]]
        ]
        trace_rows.append(row)
    trace_targets = _self_hashed(
        {
            "schema_version": "stage2_control_trace_targets.v1",
            "target_identities_file_sha256": _file_sha(identities_path),
            "target_identities_sha256": identities["target_identities_sha256"],
            "capability_report_file_sha256": _file_sha(transport_path),
            "capability_report_sha256": transport["report_sha256"],
            "capability_verification_file_sha256": _file_sha(
                transport_verification_path
            ),
            "capability_verification_sha256": transport_verification[
                "verification_sha256"
            ],
            "provider_registry_verified": False,
            "target_count": 3,
            "rpc_call_count": 6,
            "targets": trace_rows,
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
        "trace_targets_sha256",
    )
    trace_targets_path = _write_json(
        executable
        / "processed/stage2_controls/2026-08-23/control-effective-unverified-trace-targets-v1/control_trace_targets.json",
        trace_targets,
    )

    fresh_errors = [
        "base:base-official-base:trace_method_unsupported:{details}",
        "base:tenderly-base:trace_method_unsupported:{details}",
        "bsc:bnb-official-bsc:trace_method_unsupported:{details}",
        "ethereum:publicnode-ethereum:trace_method_unsupported:{details}",
    ]
    fresh = _self_hashed(
        {
            "schema_version": "stage2_control_trace_state_capability.v1",
            "complete": False,
            "errors": fresh_errors,
            "chain_count": 3,
            "chains": [],
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
        "report_sha256",
    )
    fresh_path = _write_json(
        executable
        / "reports/stage2_controls/2026-08-23/local-test-effective-trace-state-capability-v2/control_trace_state_capability.json",
        fresh,
    )
    fresh_verification = _self_hashed(
        {
            "schema_version": "stage2_control_trace_state_capability_verification.v1",
            "complete": False,
            "errors": fresh_errors,
            "report_sha256": fresh["report_sha256"],
            "report_file_sha256": _file_sha(fresh_path),
            "provider_registry_verified": False,
            "rpc_authorized": False,
            "selection_authorized": False,
            "stage_promotion_authorized": False,
            "recovery3_mutation_authorized": False,
        },
        "verification_sha256",
    )
    fresh_verification_path = _write_json(
        executable
        / "reports/stage2_controls/2026-08-23/local-test-effective-trace-state-capability-v2/control_trace_state_capability_verification.json",
        fresh_verification,
    )
    return {
        "project_root": tmp_path,
        "review_kit": review_kit,
        "historical_request": historical_path,
        "target_identities": identities_path,
        "trace_targets": trace_targets_path,
        "transport_report": transport_path,
        "transport_verification": transport_verification_path,
        "fresh_report": fresh_path,
        "fresh_verification": fresh_verification_path,
    }


def _build(paths: dict[str, Path]) -> dict[str, object]:
    return build_legacy_alias_amendment_request(
        project_root=paths["project_root"],
        review_kit_path=paths["review_kit"],
        historical_request_path=paths["historical_request"],
        target_identities_path=paths["target_identities"],
        trace_targets_path=paths["trace_targets"],
        transport_report_path=paths["transport_report"],
        transport_verification_path=paths["transport_verification"],
        fresh_report_path=paths["fresh_report"],
        fresh_verification_path=paths["fresh_verification"],
        created_at_utc="2026-08-23T00:55:54Z",
        decision_owner="zmzubraj",
    )


def test_builder_is_deterministic_scope_bound_and_non_authorizing(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request = _build(paths)

    assert request == _build(paths)
    assert request["decision"] == "AWAITING_EXPLICIT_METHOD_APPROVAL"
    assert request["effective_trace_scope"]["target_count"] == 3
    assert request["effective_trace_scope"]["rpc_call_count"] == 6
    assert request["triggering_transport_evidence"]["provider_registry_verified"] is False
    assert request["fresh_exact_registry_attempt"]["complete"] is False
    assert request["authority"] == {
        "method_approved": False,
        "provider_identity_verified": False,
        "provider_registry_verified": False,
        "rpc_authorized": False,
        "denominator_admission_authorized": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "counter_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "independent_review_established": False,
        "r5_authorized": False,
        "release_authorized": False,
        "publication_authorized": False,
    }


def test_verifier_rejects_request_and_input_tampering(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request_path = _write_json(tmp_path / "request.json", _build(paths))
    verified = verify_legacy_alias_amendment_request(
        request_path=request_path,
        project_root=paths["project_root"],
    )
    assert verified["decision"] == "LEGACY_ALIAS_AMENDMENT_REQUEST_VERIFIED_NON_AUTHORIZING"
    assert verified["method_approved"] is False
    assert verified["verification_sha256"] == _canonical_sha(
        {key: value for key, value in verified.items() if key != "verification_sha256"}
    )

    tampered = json.loads(request_path.read_text())
    tampered["authority"]["rpc_authorized"] = True
    _write_json(request_path, tampered)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasAmendmentError,
        match="request_self_hash_invalid",
    ):
        verify_legacy_alias_amendment_request(
            request_path=request_path,
            project_root=paths["project_root"],
        )

    request_path = _write_json(tmp_path / "request.json", _build(paths))
    identities = json.loads(paths["target_identities"].read_text())
    identities["targets"][0]["case_id"] = "tampered"
    _write_json(paths["target_identities"], identities)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasAmendmentError,
        match="target_identities_file_hash_mismatch",
    ):
        verify_legacy_alias_amendment_request(
            request_path=request_path,
            project_root=paths["project_root"],
        )


def test_builder_rejects_authority_overclaim_and_complete_fresh_registry(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    targets = json.loads(paths["trace_targets"].read_text())
    targets["rpc_authorized"] = True
    targets.pop("trace_targets_sha256")
    targets["trace_targets_sha256"] = _canonical_sha(targets)
    _write_json(paths["trace_targets"], targets)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasAmendmentError,
        match="trace_targets_rpc_authorized_invalid",
    ):
        _build(paths)

    paths = _inputs(tmp_path / "fresh")
    fresh = json.loads(paths["fresh_report"].read_text())
    fresh["complete"] = True
    fresh["errors"] = []
    fresh.pop("report_sha256")
    fresh["report_sha256"] = _canonical_sha(fresh)
    _write_json(paths["fresh_report"], fresh)
    fresh_verification = json.loads(paths["fresh_verification"].read_text())
    fresh_verification["complete"] = True
    fresh_verification["errors"] = []
    fresh_verification["report_sha256"] = fresh["report_sha256"]
    fresh_verification["report_file_sha256"] = _file_sha(paths["fresh_report"])
    fresh_verification.pop("verification_sha256")
    fresh_verification["verification_sha256"] = _canonical_sha(fresh_verification)
    _write_json(paths["fresh_verification"], fresh_verification)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasAmendmentError,
        match="fresh_capability_not_fail_closed",
    ):
        _build(paths)


def test_cli_builds_and_verifies_request(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "built-request.json"
    build = subprocess.run(
        [
            "uv",
            "run",
            "--project",
            str(root),
            "python",
            str(root / "build_stage2_control_provider_identity_legacy_alias_amendment_request.py"),
            "--project-root",
            str(paths["project_root"]),
            "--review-kit",
            str(paths["review_kit"]),
            "--historical-request",
            str(paths["historical_request"]),
            "--target-identities",
            str(paths["target_identities"]),
            "--trace-targets",
            str(paths["trace_targets"]),
            "--transport-report",
            str(paths["transport_report"]),
            "--transport-verification",
            str(paths["transport_verification"]),
            "--fresh-report",
            str(paths["fresh_report"]),
            "--fresh-verification",
            str(paths["fresh_verification"]),
            "--created-at-utc",
            "2026-08-23T00:55:54Z",
            "--decision-owner",
            "zmzubraj",
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    assert json.loads(output.read_text()) == _build(paths)

    verification_output = tmp_path / "request-verification.json"
    verify = subprocess.run(
        [
            "uv",
            "run",
            "--project",
            str(root),
            "python",
            str(root / "verify_stage2_control_provider_identity_legacy_alias_amendment_request.py"),
            "--project-root",
            str(paths["project_root"]),
            "--request",
            str(output),
            "--output-verification",
            str(verification_output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert verify.returncode == 0, verify.stderr
    assert "LEGACY_ALIAS_AMENDMENT_REQUEST_VERIFIED_NON_AUTHORIZING" in verify.stdout
    verification = json.loads(verification_output.read_text())
    assert verification["decision"] == (
        "LEGACY_ALIAS_AMENDMENT_REQUEST_VERIFIED_NON_AUTHORIZING"
    )
    assert verification["rpc_authorized"] is False
    assert verification["verification_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in verification.items()
            if key != "verification_sha256"
        }
    )
