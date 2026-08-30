from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition.control_trace_retry_overlay_approval import (
    APPROVED_SPEC_SHA256,
    ControlTraceRetryOverlayApprovalError,
    build_trace_retry_overlay_spec_approval,
    verify_trace_retry_overlay_spec_approval,
)


def _approval(spec: Path) -> dict[str, object]:
    return build_trace_retry_overlay_spec_approval(
        specification_path=spec,
        approval_text=(
            "APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256: "
            + APPROVED_SPEC_SHA256
        ),
        approved_by_principal="zmzubraj",
        approved_at_date="2026-08-25",
        approval_source="CODEX_CHAT_EXACT_USER_TOKEN",
    )


def test_approval_rehashes_exact_spec_and_grants_only_implementation(
    tmp_path: Path,
):
    spec = tmp_path / "design.md"
    spec.write_bytes(b"approved bytes")
    digest = hashlib.sha256(b"approved bytes").hexdigest()
    with pytest.raises(
        ControlTraceRetryOverlayApprovalError,
        match="approved_specification_mismatch",
    ):
        build_trace_retry_overlay_spec_approval(
            specification_path=spec,
            approval_text=(
                "APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256: "
                + APPROVED_SPEC_SHA256
            ),
            approved_by_principal="zmzubraj",
            approved_at_date="2026-08-25",
            approval_source="CODEX_CHAT_EXACT_USER_TOKEN",
        )
    assert digest != APPROVED_SPEC_SHA256


def test_approval_builds_and_reconstructs_the_frozen_spec(repo_root: Path):
    spec = repo_root / "docs/superpowers/specs/2026-08-25-stage2-trace-retry-overlay-v1-design.md"
    approval = _approval(spec)
    assert approval["specification_file_sha256"] == APPROVED_SPEC_SHA256
    assert approval["implementation_authorized"] is True
    for field in (
        "rpc_authorized",
        "denominator_admission_authorized",
        "selection_authorized",
        "qualification_authorized",
        "counter_authority",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
        "independent_review_established",
        "r5_authorized",
        "release_authorized",
        "publication_authorized",
    ):
        assert approval[field] is False

    record = repo_root / "approval.json"
    record.write_text(json.dumps(approval, sort_keys=True), encoding="utf-8")
    verification = verify_trace_retry_overlay_spec_approval(
        approval_path=record,
        specification_path=spec,
    )
    assert verification["decision"] == "TRACE_RETRY_OVERLAY_SPEC_APPROVAL_VERIFIED"
    assert verification["verified"] is True


def test_approval_rejects_bad_token_and_authority_escalation(
    repo_root: Path, tmp_path: Path
):
    spec = repo_root / "docs/superpowers/specs/2026-08-25-stage2-trace-retry-overlay-v1-design.md"
    with pytest.raises(ControlTraceRetryOverlayApprovalError, match="approval_digest_invalid"):
        build_trace_retry_overlay_spec_approval(
            specification_path=spec,
            approval_text=(
                "APPROVE_WRITTEN_TRACE_RETRY_OVERLAY_V1_SPEC_SHA256: " + "0" * 64
            ),
            approved_by_principal="zmzubraj",
            approved_at_date="2026-08-25",
            approval_source="CODEX_CHAT_EXACT_USER_TOKEN",
        )

    approval = _approval(spec)
    approval["rpc_authorized"] = True
    material = {k: v for k, v in approval.items() if k != "record_sha256"}
    approval["record_sha256"] = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    record = tmp_path / "approval.json"
    record.write_text(json.dumps(approval), encoding="utf-8")
    with pytest.raises(ControlTraceRetryOverlayApprovalError, match="rpc_authorized_invalid"):
        verify_trace_retry_overlay_spec_approval(
            approval_path=record,
            specification_path=spec,
        )


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]
