from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_approval import (
    APPROVAL_TOKEN,
    build_legacy_alias_approval_record,
    verify_legacy_alias_approval_record,
)
from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_revision import (
    ControlProviderIdentityLegacyAliasRevisionError,
    build_legacy_alias_identity_revision_request,
    verify_legacy_alias_identity_revision_request,
)
from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_revision_approval import (
    ControlProviderIdentityLegacyAliasRevisionApprovalError,
    build_legacy_alias_identity_revision_approval,
    canonical_signed_payload,
    verify_legacy_alias_identity_revision_approval,
)


EXECUTABLE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = EXECUTABLE_ROOT.parent
REQUEST = (
    EXECUTABLE_ROOT
    / "reports/stage2_controls/2026-08-23/"
    "provider-identity-legacy-alias-amendment-request-v2/"
    "provider_identity_legacy_alias_amendment_request.json"
)
CHAINS = ["base", "bsc", "ethereum"]
ENDPOINTS = [
    "https://base.merkle.io",
    "https://bsc.merkle.io",
    "https://eth.merkle.io",
]
CONJUNCTS = [
    "operator_domain_bridge",
    "chain_support",
    "endpoint_transport_identity",
    "frozen_runtime_capability",
    "paired_family_independence",
]


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _write(path: Path, payload: object) -> Path:
    if isinstance(payload, dict):
        data = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    else:
        data = str(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    return path


def _inputs(tmp_path: Path) -> dict[str, Path]:
    approval = build_legacy_alias_approval_record(
        project_root=PROJECT_ROOT,
        request_path=REQUEST,
        approval_text=APPROVAL_TOKEN,
        approved_by_principal="test-fixture-principal",
        approved_at_date="2026-08-23",
        approval_source="pytest_synthetic_fixture",
    )
    approval_path = _write(tmp_path / "approval.json", approval)
    approval_verification = verify_legacy_alias_approval_record(
        project_root=PROJECT_ROOT,
        request_path=REQUEST,
        approval_path=approval_path,
    )
    approval_verification_path = _write(
        tmp_path / "approval-verification.json", approval_verification
    )

    evidence_root = tmp_path / "evidence"
    rows = []
    for conjunct_id in CONJUNCTS:
        evidence_file = _write(
            evidence_root / f"{conjunct_id}.txt",
            f"synthetic evidence fixture for {conjunct_id}\n",
        )
        rows.append(
            {
                "conjunct_id": conjunct_id,
                "status": "PRESENT_FOR_ACCOUNTABLE_REVIEW",
                "chains": CHAINS if conjunct_id != "operator_domain_bridge" else [],
                "endpoints": (
                    ENDPOINTS
                    if conjunct_id
                    in {"endpoint_transport_identity", "frozen_runtime_capability"}
                    else []
                ),
                "evidence_files": [
                    {
                        "path": evidence_file.name,
                        "file_sha256": hashlib.sha256(
                            evidence_file.read_bytes()
                        ).hexdigest(),
                    }
                ],
            }
        )
    manifest = {
        "schema_version": (
            "chronosaudit.control_provider_identity_legacy_alias_evidence_packet.v1"
        ),
        "decision": "EVIDENCE_PACKET_ASSEMBLED_NON_AUTHORIZING",
        "request_sha256": json.loads(REQUEST.read_text())["request_sha256"],
        "approval_record_sha256": approval["record_sha256"],
        "conjuncts": rows,
        "provider_identity_verified": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest["evidence_packet_sha256"] = _canonical_sha(manifest)
    manifest_path = _write(evidence_root / "evidence-packet.json", manifest)
    return {
        "approval": approval_path,
        "approval_verification": approval_verification_path,
        "evidence_root": evidence_root,
        "evidence_manifest": manifest_path,
    }


def _build(tmp_path: Path) -> dict[str, object]:
    inputs = _inputs(tmp_path)
    return build_legacy_alias_identity_revision_request(
        project_root=PROJECT_ROOT,
        request_path=REQUEST,
        approval_path=inputs["approval"],
        approval_verification_path=inputs["approval_verification"],
        evidence_manifest_path=inputs["evidence_manifest"],
        evidence_root=inputs["evidence_root"],
        created_at_utc="2026-08-23T12:00:00Z",
        expires_at_utc="2026-08-30T12:00:00Z",
        reviewer_principal="test-fixture-identity-reviewer",
    )


def test_builds_non_authorizing_exact_scope_revision_request(tmp_path: Path) -> None:
    revision = _build(tmp_path)
    assert revision["decision"] == (
        "AWAITING_ACCOUNTABLE_PROVIDER_IDENTITY_REVISION_SIGNATURE"
    )
    assert revision["legacy_provider_count"] == 3
    assert revision["paired_provider_count"] == 3
    assert [row["chain"] for row in revision["legacy_provider_bindings"]] == CHAINS
    assert [row["endpoint"] for row in revision["legacy_provider_bindings"]] == ENDPOINTS
    assert revision["method_approved"] is True
    assert revision["provider_identity_verified"] is False
    assert revision["rpc_authorized"] is False
    assert revision["selection_authorized"] is False
    assert revision["revision_request_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in revision.items()
            if key != "revision_request_sha256"
        }
    )


def test_reconstructs_exact_revision_request(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    revision = build_legacy_alias_identity_revision_request(
        project_root=PROJECT_ROOT,
        request_path=REQUEST,
        approval_path=inputs["approval"],
        approval_verification_path=inputs["approval_verification"],
        evidence_manifest_path=inputs["evidence_manifest"],
        evidence_root=inputs["evidence_root"],
        created_at_utc="2026-08-23T12:00:00Z",
        expires_at_utc="2026-08-30T12:00:00Z",
        reviewer_principal="test-fixture-identity-reviewer",
    )
    revision_path = _write(tmp_path / "revision-request.json", revision)
    verification = verify_legacy_alias_identity_revision_request(
        project_root=PROJECT_ROOT,
        request_path=REQUEST,
        approval_path=inputs["approval"],
        approval_verification_path=inputs["approval_verification"],
        evidence_manifest_path=inputs["evidence_manifest"],
        evidence_root=inputs["evidence_root"],
        revision_request_path=revision_path,
    )
    assert verification["decision"] == (
        "LEGACY_ALIAS_IDENTITY_REVISION_REQUEST_VERIFIED_NON_AUTHORIZING"
    )
    assert verification["provider_identity_verified"] is False
    assert verification["rpc_authorized"] is False


def test_missing_conjunct_and_hash_tampering_fail_closed(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    manifest = json.loads(inputs["evidence_manifest"].read_text())
    manifest["conjuncts"].pop()
    manifest["evidence_packet_sha256"] = _canonical_sha(
        {
            key: value
            for key, value in manifest.items()
            if key != "evidence_packet_sha256"
        }
    )
    _write(inputs["evidence_manifest"], manifest)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasRevisionError,
        match="evidence_conjunct_scope_invalid",
    ):
        build_legacy_alias_identity_revision_request(
            project_root=PROJECT_ROOT,
            request_path=REQUEST,
            approval_path=inputs["approval"],
            approval_verification_path=inputs["approval_verification"],
            evidence_manifest_path=inputs["evidence_manifest"],
            evidence_root=inputs["evidence_root"],
            created_at_utc="2026-08-23T12:00:00Z",
            expires_at_utc="2026-08-30T12:00:00Z",
            reviewer_principal="test-fixture-identity-reviewer",
        )

    inputs = _inputs(tmp_path / "hash-tamper")
    evidence = inputs["evidence_root"] / "operator_domain_bridge.txt"
    evidence.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(
        ControlProviderIdentityLegacyAliasRevisionError,
        match="evidence_file_hash_mismatch",
    ):
        build_legacy_alias_identity_revision_request(
            project_root=PROJECT_ROOT,
            request_path=REQUEST,
            approval_path=inputs["approval"],
            approval_verification_path=inputs["approval_verification"],
            evidence_manifest_path=inputs["evidence_manifest"],
            evidence_root=inputs["evidence_root"],
            created_at_utc="2026-08-23T12:00:00Z",
            expires_at_utc="2026-08-30T12:00:00Z",
            reviewer_principal="test-fixture-identity-reviewer",
        )


def test_expiry_and_authority_overclaim_fail_closed(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasRevisionError,
        match="review_window_invalid",
    ):
        build_legacy_alias_identity_revision_request(
            project_root=PROJECT_ROOT,
            request_path=REQUEST,
            approval_path=inputs["approval"],
            approval_verification_path=inputs["approval_verification"],
            evidence_manifest_path=inputs["evidence_manifest"],
            evidence_root=inputs["evidence_root"],
            created_at_utc="2026-08-30T12:00:00Z",
            expires_at_utc="2026-08-23T12:00:00Z",
            reviewer_principal="test-fixture-identity-reviewer",
        )

    revision = _build(tmp_path / "authority")
    revision["rpc_authorized"] = True
    revision["revision_request_sha256"] = _canonical_sha(
        {
            key: value
            for key, value in revision.items()
            if key != "revision_request_sha256"
        }
    )
    revision_path = _write(tmp_path / "authority-overclaim.json", revision)
    inputs = _inputs(tmp_path / "authority-inputs")
    with pytest.raises(
        ControlProviderIdentityLegacyAliasRevisionError,
        match="revision_rpc_authorized_invalid",
    ):
        verify_legacy_alias_identity_revision_request(
            project_root=PROJECT_ROOT,
            request_path=REQUEST,
            approval_path=inputs["approval"],
            approval_verification_path=inputs["approval_verification"],
            evidence_manifest_path=inputs["evidence_manifest"],
            evidence_root=inputs["evidence_root"],
            revision_request_path=revision_path,
        )


def test_cli_atomically_builds_and_verifies_synthetic_packet(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    revision_path = tmp_path / "revision-request.json"
    verification_path = tmp_path / "revision-verification.json"
    built = subprocess.run(
        [
            str(EXECUTABLE_ROOT / ".venv/bin/python"),
            str(
                EXECUTABLE_ROOT
                / "build_stage2_control_provider_identity_legacy_alias_revision_request.py"
            ),
            "--project-root",
            str(PROJECT_ROOT),
            "--request",
            str(REQUEST),
            "--approval",
            str(inputs["approval"]),
            "--approval-verification",
            str(inputs["approval_verification"]),
            "--evidence-manifest",
            str(inputs["evidence_manifest"]),
            "--evidence-root",
            str(inputs["evidence_root"]),
            "--created-at-utc",
            "2026-08-23T12:00:00Z",
            "--expires-at-utc",
            "2026-08-30T12:00:00Z",
            "--reviewer-principal",
            "test-fixture-identity-reviewer",
            "--output",
            str(revision_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    assert revision_path.is_file()
    verified = subprocess.run(
        [
            str(EXECUTABLE_ROOT / ".venv/bin/python"),
            str(
                EXECUTABLE_ROOT
                / "verify_stage2_control_provider_identity_legacy_alias_revision_request.py"
            ),
            "--project-root",
            str(PROJECT_ROOT),
            "--request",
            str(REQUEST),
            "--approval",
            str(inputs["approval"]),
            "--approval-verification",
            str(inputs["approval_verification"]),
            "--evidence-manifest",
            str(inputs["evidence_manifest"]),
            "--evidence-root",
            str(inputs["evidence_root"]),
            "--revision-request",
            str(revision_path),
            "--output-verification",
            str(verification_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    assert verification["provider_identity_verified"] is False
    assert verification["rpc_authorized"] is False


def _revision_chain(tmp_path: Path) -> dict[str, Path]:
    inputs = _inputs(tmp_path)
    revision = build_legacy_alias_identity_revision_request(
        project_root=PROJECT_ROOT,
        request_path=REQUEST,
        approval_path=inputs["approval"],
        approval_verification_path=inputs["approval_verification"],
        evidence_manifest_path=inputs["evidence_manifest"],
        evidence_root=inputs["evidence_root"],
        created_at_utc="2026-08-23T12:00:00Z",
        expires_at_utc="2026-08-30T12:00:00Z",
        reviewer_principal="test-fixture-identity-reviewer",
    )
    revision_path = _write(tmp_path / "revision-request.json", revision)
    verification = verify_legacy_alias_identity_revision_request(
        project_root=PROJECT_ROOT,
        request_path=REQUEST,
        approval_path=inputs["approval"],
        approval_verification_path=inputs["approval_verification"],
        evidence_manifest_path=inputs["evidence_manifest"],
        evidence_root=inputs["evidence_root"],
        revision_request_path=revision_path,
    )
    verification_path = _write(
        tmp_path / "revision-request-verification.json", verification
    )
    return {
        **inputs,
        "revision": revision_path,
        "revision_verification": verification_path,
    }


def _sign_revision(
    tmp_path: Path, approval: dict[str, object]
) -> tuple[Path, Path, Path]:
    key = tmp_path / "synthetic-review-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    message = tmp_path / "revision-approval.json"
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
            "chronosaudit-stage2-control-provider-identity-legacy-alias-v1",
            str(message),
        ],
        check=True,
    )
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(
        "test-fixture-identity-reviewer "
        + Path(f"{key}.pub").read_text(encoding="utf-8").strip()
        + "\n",
        encoding="utf-8",
    )
    return message, Path(f"{message}.sig"), allowed


def test_signed_revision_approval_is_exact_and_non_rpc(tmp_path: Path) -> None:
    chain = _revision_chain(tmp_path)
    approval = build_legacy_alias_identity_revision_approval(
        revision_request_path=chain["revision"],
        revision_verification_path=chain["revision_verification"],
        reviewer_principal="test-fixture-identity-reviewer",
    )
    assert approval["decision"] == (
        "APPROVE_LOCAL_TEST_LEGACY_ALIAS_PROVIDER_IDENTITY_REVISION"
    )
    assert approval["provider_identity_revision_authorized"] is True
    assert approval["registry_fragment_projection_authorized"] is True
    assert approval["identity_report_projection_authorized"] is True
    assert approval["rpc_authorized"] is False
    assert approval["selection_authorized"] is False
    assert approval["counter_authority"] is False


def test_valid_signature_projects_exact_local_test_identity_only(
    tmp_path: Path,
) -> None:
    chain = _revision_chain(tmp_path)
    approval = build_legacy_alias_identity_revision_approval(
        revision_request_path=chain["revision"],
        revision_verification_path=chain["revision_verification"],
        reviewer_principal="test-fixture-identity-reviewer",
    )
    approval_path, signature, allowed = _sign_revision(tmp_path, approval)
    result = verify_legacy_alias_identity_revision_approval(
        revision_request_path=chain["revision"],
        revision_verification_path=chain["revision_verification"],
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="test-fixture-identity-reviewer",
        verification_time_utc="2026-08-24T12:00:00Z",
    )
    verification = result["verification"]
    assert verification["decision"] == (
        "LEGACY_ALIAS_PROVIDER_IDENTITY_REVISION_VERIFIED_LOCAL_TEST_ONLY"
    )
    assert verification["provider_identity_verified"] is True
    assert verification["target_identities_sha256"] == approval[
        "target_identities_sha256"
    ]
    assert verification["trace_targets_sha256"] == approval[
        "trace_targets_sha256"
    ]
    assert verification["rpc_authorized"] is False
    registry = result["provider_registry_fragment"]
    assert [row["endpoint"] for row in registry["providers"]] == ENDPOINTS
    assert {
        row["operator_family"] for row in registry["providers"]
    } == {"merkle"}
    assert {
        row["operator_identity_family"] for row in registry["providers"]
    } == {"merkle_blink"}
    assert registry["rpc_authorized"] is False
    identity = result["provider_identity_verification"]
    assert identity["complete"] is True
    assert identity["chain_count"] == 3
    assert all(row["provider_count"] == 2 for row in identity["chains"])
    assert all(
        "merkle" in row["verified_operator_families"]
        for row in identity["chains"]
    )
    assert identity["rpc_authorized"] is False


def test_signed_revision_rejects_tampering_wrong_principal_and_expiry(
    tmp_path: Path,
) -> None:
    chain = _revision_chain(tmp_path)
    approval = build_legacy_alias_identity_revision_approval(
        revision_request_path=chain["revision"],
        revision_verification_path=chain["revision_verification"],
        reviewer_principal="test-fixture-identity-reviewer",
    )
    approval_path, signature, allowed = _sign_revision(tmp_path, approval)
    tampered = dict(approval)
    tampered["rpc_authorized"] = True
    _write(approval_path, tampered)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasRevisionApprovalError,
        match="approval_rpc_authorized_invalid",
    ):
        verify_legacy_alias_identity_revision_approval(
            revision_request_path=chain["revision"],
            revision_verification_path=chain["revision_verification"],
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="test-fixture-identity-reviewer",
            verification_time_utc="2026-08-24T12:00:00Z",
        )

    _write(approval_path, approval)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasRevisionApprovalError,
        match="reviewer_principal_mismatch",
    ):
        verify_legacy_alias_identity_revision_approval(
            revision_request_path=chain["revision"],
            revision_verification_path=chain["revision_verification"],
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="wrong-principal",
            verification_time_utc="2026-08-24T12:00:00Z",
        )
    with pytest.raises(
        ControlProviderIdentityLegacyAliasRevisionApprovalError,
        match="review_expired",
    ):
        verify_legacy_alias_identity_revision_approval(
            revision_request_path=chain["revision"],
            revision_verification_path=chain["revision_verification"],
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="test-fixture-identity-reviewer",
            verification_time_utc="2026-08-31T12:00:00Z",
        )


def test_signed_revision_cli_atomically_builds_and_projects_identity_only(
    tmp_path: Path,
) -> None:
    chain = _revision_chain(tmp_path)
    approval_path = tmp_path / "signed-approval.json"
    signing_payload_path = tmp_path / "signed-approval.payload"
    built = subprocess.run(
        [
            str(EXECUTABLE_ROOT / ".venv/bin/python"),
            str(
                EXECUTABLE_ROOT
                / "build_stage2_control_provider_identity_legacy_alias_revision_approval.py"
            ),
            "--revision-request",
            str(chain["revision"]),
            "--revision-verification",
            str(chain["revision_verification"]),
            "--reviewer-principal",
            "test-fixture-identity-reviewer",
            "--output-approval",
            str(approval_path),
            "--output-signing-payload",
            str(signing_payload_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    assert signing_payload_path.read_bytes() == canonical_signed_payload(approval)
    assert approval["rpc_authorized"] is False

    key = tmp_path / "synthetic-cli-review-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-q",
            "-f",
            str(key),
            "-n",
            "chronosaudit-stage2-control-provider-identity-legacy-alias-v1",
            str(signing_payload_path),
        ],
        check=True,
    )
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(
        "test-fixture-identity-reviewer "
        + Path(f"{key}.pub").read_text(encoding="utf-8").strip()
        + "\n",
        encoding="utf-8",
    )
    verification_path = tmp_path / "signed-verification.json"
    registry_path = tmp_path / "registry-fragment.json"
    identity_path = tmp_path / "identity-verification.json"
    verified = subprocess.run(
        [
            str(EXECUTABLE_ROOT / ".venv/bin/python"),
            str(
                EXECUTABLE_ROOT
                / "verify_stage2_control_provider_identity_legacy_alias_revision_approval.py"
            ),
            "--revision-request",
            str(chain["revision"]),
            "--revision-verification",
            str(chain["revision_verification"]),
            "--approval",
            str(approval_path),
            "--signature",
            str(Path(f"{signing_payload_path}.sig")),
            "--allowed-signers",
            str(allowed),
            "--expected-principal",
            "test-fixture-identity-reviewer",
            "--verification-time-utc",
            "2026-08-24T12:00:00Z",
            "--output-verification",
            str(verification_path),
            "--output-registry-fragment",
            str(registry_path),
            "--output-identity-verification",
            str(identity_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    assert verification["provider_identity_verified"] is True
    assert verification["rpc_authorized"] is False
    assert registry["provider_count"] == 3
    assert registry["rpc_authorized"] is False
    assert identity["complete"] is True
    assert identity["rpc_authorized"] is False
