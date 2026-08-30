from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_acquisition_approval import (
    ControlAcquisitionApprovalError,
    build_control_acquisition_approval,
    build_control_acquisition_approval_request,
    canonical_signed_payload,
    verify_control_acquisition_approval,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_plan(tmp_path: Path) -> tuple[Path, Path]:
    plan_path = tmp_path / "chunk-plan.csv"
    rows = [
        {
            "chunk_id": "stage2-expansion-0001-aaaaaaaaaaaa",
            "chunk_sequence": 1,
            "chunk_case_position": 1,
            "case_name": "case-1",
            "chain": "ethereum",
            "minimum_additional_distinct_slots": 9,
            "expansion_requirement_sha256": "1" * 64,
            "chunk_scope_sha256": "a" * 64,
            "acquisition_authorized": False,
            "rpc_authorized": False,
            "selection_authorized": False,
        },
        {
            "chunk_id": "stage2-expansion-0002-bbbbbbbbbbbb",
            "chunk_sequence": 2,
            "chunk_case_position": 1,
            "case_name": "case-2",
            "chain": "bsc",
            "minimum_additional_distinct_slots": 8,
            "expansion_requirement_sha256": "2" * 64,
            "chunk_scope_sha256": "b" * 64,
            "acquisition_authorized": False,
            "rpc_authorized": False,
            "selection_authorized": False,
        },
    ]
    pd.DataFrame(rows).to_csv(plan_path, index=False)
    manifest = {
        "schema_version": "chronosaudit.control_denominator_expansion_chunk_plan.v1",
        "decision": "BOUNDED_EXPANSION_PLAN_AWAITS_ACCOUNTABLE_ACQUISITION_APPROVAL",
        "acquisition_authorized": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "chunk_count": 2,
        "cases_requiring_expansion": 2,
        "minimum_additional_distinct_slots": 17,
        "case_overlap_count": 0,
        "requirement_overlap_count": 0,
        "plan_no_repeat_sha256": "c" * 64,
        "inputs": {
            "authority_projection_sha256": "d" * 64,
            "expansion_ledger_sha256": "e" * 64,
            "pair_scope_manifest_sha256": "f" * 64,
            "policy_sha256": "0" * 64,
        },
        "chunks": [
            {
                "chunk_id": rows[0]["chunk_id"],
                "chunk_sequence": 1,
                "case_count": 1,
                "minimum_additional_distinct_slots": 9,
                "chunk_scope_sha256": "a" * 64,
                "acquisition_authorized": False,
                "rpc_authorized": False,
                "selection_authorized": False,
            },
            {
                "chunk_id": rows[1]["chunk_id"],
                "chunk_sequence": 2,
                "case_count": 1,
                "minimum_additional_distinct_slots": 8,
                "chunk_scope_sha256": "b" * 64,
                "acquisition_authorized": False,
                "rpc_authorized": False,
                "selection_authorized": False,
            },
        ],
        "output": {"path": str(plan_path), "sha256": _sha256_file(plan_path)},
    }
    manifest_path = tmp_path / "chunk-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return plan_path, manifest_path


def _approval(request: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "chronosaudit.control_source_acquisition_approval.v2",
        "request_sha256": request["request_sha256"],
        "signer_principal": "methods-owner@example.org",
        "decision": "APPROVE_HISTORICAL_DENOMINATOR_SOURCE_ACQUISITION",
        "purpose": "HISTORICAL_DENOMINATOR_EXPANSION_ONLY",
        "approval_start_utc": "2026-08-17T20:00:00Z",
        "approval_expires_utc": "2026-08-18T20:00:00Z",
        "query_plan_sha256": request["query_plan_sha256"],
        "approved_chunk_scope_sha256s": request["chunk_scope_sha256s"],
        "chain_allowlist": request["chains"],
        "source_object_count": request["source_object_count"],
        "maximum_download_bytes": request["maximum_download_bytes"],
        "raw_receipts_required": True,
        "accepted_import_ledger_required": True,
        "acquisition_authorized": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }


def _sign(
    tmp_path: Path, approval: dict[str, object]
) -> tuple[Path, Path, Path]:
    key = tmp_path / "approval-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    message = tmp_path / "approval-message.json"
    message.write_bytes(canonical_signed_payload(approval))
    subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-q",
            "-f",
            str(key),
            "-n",
            "chronosaudit-stage2-control-source-acquisition-v2",
            str(message),
        ],
        check=True,
    )
    signature = Path(f"{message}.sig")
    allowed_signers = tmp_path / "allowed-signers"
    public_key = Path(f"{key}.pub").read_text(encoding="utf-8").strip()
    allowed_signers.write_text(
        f"methods-owner@example.org {public_key}\n", encoding="utf-8"
    )
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    return approval_path, signature, allowed_signers


def test_request_is_deterministic_and_non_authorizing(tmp_path: Path) -> None:
    plan, manifest = _write_plan(tmp_path)

    request = build_control_acquisition_approval_request(
        chunk_plan_path=plan,
        chunk_manifest_path=manifest,
        query_plan_sha256="9" * 64,
        source_object_count=43,
        maximum_download_bytes=5_024_970_903,
    )
    repeated = build_control_acquisition_approval_request(
        chunk_plan_path=plan,
        chunk_manifest_path=manifest,
        query_plan_sha256="9" * 64,
        source_object_count=43,
        maximum_download_bytes=5_024_970_903,
    )

    assert request == repeated
    assert request["decision"] == "AWAITING_ACCOUNTABLE_SIGNED_APPROVAL"
    assert request["chunk_count"] == 2
    assert request["case_count"] == 2
    assert request["minimum_additional_distinct_slots"] == 17
    assert request["source_object_count"] == 43
    assert request["maximum_download_bytes"] == 5_024_970_903
    assert request["acquisition_authorized"] is False
    assert request["rpc_authorized"] is False
    assert request["selection_authorized"] is False
    assert len(request["request_sha256"]) == 64


def test_missing_query_plan_remains_not_approvable(tmp_path: Path) -> None:
    plan, manifest = _write_plan(tmp_path)

    request = build_control_acquisition_approval_request(
        chunk_plan_path=plan,
        chunk_manifest_path=manifest,
        query_plan_sha256=None,
        source_object_count=None,
        maximum_download_bytes=None,
    )

    assert request["decision"] == "AWAITING_FROZEN_QUERY_PLAN"
    assert request["query_plan_sha256"] is None


def test_approval_builder_is_deterministic_and_source_only(tmp_path: Path) -> None:
    plan, manifest = _write_plan(tmp_path)
    request = build_control_acquisition_approval_request(
        chunk_plan_path=plan,
        chunk_manifest_path=manifest,
        query_plan_sha256="9" * 64,
        source_object_count=43,
        maximum_download_bytes=5_024_970_903,
    )

    approval = build_control_acquisition_approval(
        request=request,
        signer_principal="methods-owner@example.org",
        approval_start_utc="2026-08-17T20:00:00Z",
        approval_expires_utc="2026-08-18T20:00:00Z",
    )
    repeated = build_control_acquisition_approval(
        request=request,
        signer_principal="methods-owner@example.org",
        approval_start_utc="2026-08-17T20:00:00Z",
        approval_expires_utc="2026-08-18T20:00:00Z",
    )

    assert approval == repeated
    assert approval["request_sha256"] == request["request_sha256"]
    assert approval["approved_chunk_scope_sha256s"] == request[
        "chunk_scope_sha256s"
    ]
    assert approval["source_object_count"] == 43
    assert approval["maximum_download_bytes"] == 5_024_970_903
    assert approval["acquisition_authorized"] is True
    assert approval["rpc_authorized"] is False
    assert approval["selection_authorized"] is False
    assert approval["stage_promotion_authorized"] is False
    assert approval["recovery3_mutation_authorized"] is False


def test_valid_openssh_signed_approval_is_verified(tmp_path: Path) -> None:
    plan, manifest = _write_plan(tmp_path)
    request = build_control_acquisition_approval_request(
        chunk_plan_path=plan,
        chunk_manifest_path=manifest,
        query_plan_sha256="9" * 64,
        source_object_count=43,
        maximum_download_bytes=5_024_970_903,
    )
    approval = _approval(request)
    approval_path, signature, allowed_signers = _sign(tmp_path, approval)

    report = verify_control_acquisition_approval(
        request=request,
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed_signers,
        expected_principal="methods-owner@example.org",
        verification_time_utc="2026-08-18T00:00:00Z",
    )

    assert report["decision"] == "SOURCE_ACQUISITION_APPROVAL_VERIFIED"
    assert report["acquisition_authorized"] is True
    assert report["rpc_authorized"] is False
    assert report["selection_authorized"] is False
    assert report["approved_chunk_count"] == 2
    assert report["identity_binding_limit"] == (
        "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_IDENTITY"
    )


def test_signed_approval_rejects_tamper_or_expiry(tmp_path: Path) -> None:
    plan, manifest = _write_plan(tmp_path)
    request = build_control_acquisition_approval_request(
        chunk_plan_path=plan,
        chunk_manifest_path=manifest,
        query_plan_sha256="9" * 64,
        source_object_count=43,
        maximum_download_bytes=5_024_970_903,
    )
    approval = _approval(request)
    approval_path, signature, allowed_signers = _sign(tmp_path, approval)
    tampered = json.loads(approval_path.read_text(encoding="utf-8"))
    tampered["approval_expires_utc"] = "2026-08-19T20:00:00Z"
    approval_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ControlAcquisitionApprovalError, match="signature_invalid"):
        verify_control_acquisition_approval(
            request=request,
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed_signers,
            expected_principal="methods-owner@example.org",
            verification_time_utc="2026-08-18T00:00:00Z",
        )

    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    with pytest.raises(ControlAcquisitionApprovalError, match="approval_expired"):
        verify_control_acquisition_approval(
            request=request,
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed_signers,
            expected_principal="methods-owner@example.org",
            verification_time_utc="2026-08-19T00:00:00Z",
        )


def test_source_approval_cannot_authorize_rpc(tmp_path: Path) -> None:
    plan, manifest = _write_plan(tmp_path)
    request = build_control_acquisition_approval_request(
        chunk_plan_path=plan,
        chunk_manifest_path=manifest,
        query_plan_sha256="9" * 64,
        source_object_count=43,
        maximum_download_bytes=5_024_970_903,
    )
    approval = _approval(request)
    approval["rpc_authorized"] = True
    approval_path, signature, allowed_signers = _sign(tmp_path, approval)

    with pytest.raises(ControlAcquisitionApprovalError, match="approval_rpc_authorized_invalid"):
        verify_control_acquisition_approval(
            request=request,
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed_signers,
            expected_principal="methods-owner@example.org",
            verification_time_utc="2026-08-18T00:00:00Z",
        )
