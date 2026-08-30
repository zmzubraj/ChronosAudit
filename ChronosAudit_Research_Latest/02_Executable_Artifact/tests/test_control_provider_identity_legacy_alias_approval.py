from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_approval import (
    APPROVAL_TOKEN,
    ControlProviderIdentityLegacyAliasApprovalError,
    build_legacy_alias_approval_record,
    verify_legacy_alias_approval_record,
)


EXECUTABLE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = EXECUTABLE_ROOT.parent
REQUEST = (
    EXECUTABLE_ROOT
    / "reports/stage2_controls/2026-08-23/"
    "provider-identity-legacy-alias-amendment-request-v2/"
    "provider_identity_legacy_alias_amendment_request.json"
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def _approval() -> dict[str, object]:
    return build_legacy_alias_approval_record(
        project_root=PROJECT_ROOT,
        request_path=REQUEST,
        approval_text=APPROVAL_TOKEN,
        approved_by_principal="test-fixture-principal",
        approved_at_date="2026-08-23",
        approval_source="pytest_synthetic_fixture",
    )


def test_build_and_verify_exact_scope_approval(tmp_path: Path) -> None:
    approval = _approval()
    assert approval["decision"] == APPROVAL_TOKEN
    assert approval["method_approved"] is True
    assert approval["provider_identity_verified"] is False
    assert approval["rpc_authorized"] is False
    assert approval["selection_authorized"] is False
    assert approval["counter_authority"] is False
    assert approval["record_sha256"] == _canonical_sha(
        {key: value for key, value in approval.items() if key != "record_sha256"}
    )

    approval_path = _write_json(tmp_path / "approval.json", approval)
    verification = verify_legacy_alias_approval_record(
        project_root=PROJECT_ROOT,
        request_path=REQUEST,
        approval_path=approval_path,
    )
    assert verification["decision"] == (
        "LEGACY_ALIAS_METHOD_APPROVAL_VERIFIED_LOCAL_TEST_ONLY"
    )
    assert verification["method_approved"] is True
    assert verification["provider_identity_verified"] is False
    assert verification["rpc_authorized"] is False
    assert verification["verification_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in verification.items()
            if key != "verification_sha256"
        }
    )


def test_wrong_token_and_authority_overclaim_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(
        ControlProviderIdentityLegacyAliasApprovalError,
        match="approval_text_invalid",
    ):
        build_legacy_alias_approval_record(
            project_root=PROJECT_ROOT,
            request_path=REQUEST,
            approval_text="APPROVE_LEGACY_ENDPOINT_ALIAS_EVIDENCE_V1_FOR_LOCAL_TEST_ONLY",
            approved_by_principal="test-fixture-principal",
            approved_at_date="2026-08-23",
            approval_source="pytest_synthetic_fixture",
        )

    approval = _approval()
    approval["rpc_authorized"] = True
    approval["record_sha256"] = _canonical_sha(
        {key: value for key, value in approval.items() if key != "record_sha256"}
    )
    approval_path = _write_json(tmp_path / "overclaim.json", approval)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasApprovalError,
        match="approval_rpc_authorized_invalid",
    ):
        verify_legacy_alias_approval_record(
            project_root=PROJECT_ROOT,
            request_path=REQUEST,
            approval_path=approval_path,
        )


def test_request_and_record_tampering_fail_closed(tmp_path: Path) -> None:
    approval = _approval()
    approval["request_sha256"] = "0" * 64
    approval["record_sha256"] = _canonical_sha(
        {key: value for key, value in approval.items() if key != "record_sha256"}
    )
    approval_path = _write_json(tmp_path / "request-tamper.json", approval)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasApprovalError,
        match="approval_reconstruction_mismatch",
    ):
        verify_legacy_alias_approval_record(
            project_root=PROJECT_ROOT,
            request_path=REQUEST,
            approval_path=approval_path,
        )

    approval = _approval()
    approval["approved_by_principal"] = "tampered"
    approval_path = _write_json(tmp_path / "record-tamper.json", approval)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasApprovalError,
        match="approval_self_hash_invalid",
    ):
        verify_legacy_alias_approval_record(
            project_root=PROJECT_ROOT,
            request_path=REQUEST,
            approval_path=approval_path,
        )


def test_cli_is_atomic_and_refuses_nonexact_token(tmp_path: Path) -> None:
    build_cli = EXECUTABLE_ROOT / (
        "build_stage2_control_provider_identity_legacy_alias_approval.py"
    )
    verify_cli = EXECUTABLE_ROOT / (
        "verify_stage2_control_provider_identity_legacy_alias_approval.py"
    )
    approval_path = tmp_path / "approval.json"
    bad = subprocess.run(
        [
            str(EXECUTABLE_ROOT / ".venv/bin/python"),
            str(build_cli),
            "--project-root",
            str(PROJECT_ROOT),
            "--request",
            str(REQUEST),
            "--approval-text",
            "APPROVE_WRONG_TOKEN",
            "--approved-by-principal",
            "test-fixture-principal",
            "--approved-at-date",
            "2026-08-23",
            "--approval-source",
            "pytest_synthetic_fixture",
            "--output",
            str(approval_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert bad.returncode != 0
    assert not approval_path.exists()

    good = subprocess.run(
        [
            str(EXECUTABLE_ROOT / ".venv/bin/python"),
            str(build_cli),
            "--project-root",
            str(PROJECT_ROOT),
            "--request",
            str(REQUEST),
            "--approval-text",
            APPROVAL_TOKEN,
            "--approved-by-principal",
            "test-fixture-principal",
            "--approved-at-date",
            "2026-08-23",
            "--approval-source",
            "pytest_synthetic_fixture",
            "--output",
            str(approval_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert good.returncode == 0, good.stderr
    assert approval_path.is_file()

    verification_path = tmp_path / "verification.json"
    verified = subprocess.run(
        [
            str(EXECUTABLE_ROOT / ".venv/bin/python"),
            str(verify_cli),
            "--project-root",
            str(PROJECT_ROOT),
            "--request",
            str(REQUEST),
            "--approval",
            str(approval_path),
            "--output-verification",
            str(verification_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    assert verification["method_approved"] is True
    assert verification["rpc_authorized"] is False
