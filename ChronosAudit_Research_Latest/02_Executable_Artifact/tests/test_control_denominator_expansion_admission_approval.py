from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from test_control_denominator_expansion_admission import _fixture, _sha, _write_json

from chronosaudit_stage2.public_acquisition.control_denominator_expansion_admission import (
    build_denominator_expansion_admission_projection,
    verify_denominator_expansion_admission_projection,
)
from chronosaudit_stage2.public_acquisition.control_denominator_expansion_admission_approval import (
    ControlDenominatorExpansionAdmissionApprovalError,
    SIGNATURE_NAMESPACE,
    build_denominator_expansion_admission_approval,
    canonical_signed_payload,
    verify_denominator_expansion_admission_approval,
)


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _signed_fixture(tmp_path: Path) -> dict[str, Path | str]:
    inputs = _fixture(tmp_path)
    projection = build_denominator_expansion_admission_projection(**inputs)
    projection_path = _write_json(tmp_path / "projection.json", projection)
    verification = verify_denominator_expansion_admission_projection(
        projection=projection, **inputs
    )
    projection_verification_path = _write_json(
        tmp_path / "projection-verification.json", verification
    )

    key = tmp_path / "accountable-key"
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    public_key = Path(f"{key}.pub")
    principal = "accountable-human"
    allowed_signers = tmp_path / "allowed-signers"
    key_parts = public_key.read_text(encoding="utf-8").split()
    allowed_signers.write_text(
        f"{principal} {key_parts[0]} {key_parts[1]}\n", encoding="utf-8"
    )
    fingerprint = subprocess.run(
        ["/usr/bin/ssh-keygen", "-lf", str(public_key), "-E", "sha256"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()[1]
    binding = {
        "schema_version": "chronosaudit.accountable_signer_identity_binding.v1",
        "decision": "ACCOUNTABLE_HUMAN_SIGNER_IDENTITY_BOUND",
        "principal": principal,
        "public_key_fingerprint": fingerprint,
        "authority_scope": "DENOMINATOR_EXPANSION_ADMISSION_V1",
        "valid_from_utc": "2026-08-23T00:00:00Z",
        "expires_at_utc": "2026-08-24T00:00:00Z",
        "accountable_human_bound": True,
        "mechanical_runtime_key": False,
        "independent_review_established": False,
        "selection_authorized": False,
        "qualification_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
        "r5_authorized": False,
        "release_authorized": False,
        "publication_authorized": False,
    }
    binding["binding_sha256"] = _sha(binding)
    binding_path = _write_json(tmp_path / "identity-binding.json", binding)
    approval = build_denominator_expansion_admission_approval(
        projection_path=projection_path,
        projection_verification_path=projection_verification_path,
        signer_identity_binding_path=binding_path,
        signer_public_key_path=public_key,
        signer_principal=principal,
    )
    approval_path = _write_json(tmp_path / "approval.json", approval)
    message = tmp_path / "message.json"
    message.write_bytes(canonical_signed_payload(approval))
    subprocess.run(
        [
            "/usr/bin/ssh-keygen", "-Y", "sign", "-q", "-f", str(key),
            "-n", SIGNATURE_NAMESPACE, str(message),
        ],
        check=True,
    )
    return {
        "projection_path": projection_path,
        "projection_verification_path": projection_verification_path,
        "signer_identity_binding_path": binding_path,
        "signer_public_key_path": public_key,
        "approval_path": approval_path,
        "signature_path": Path(f"{message}.sig"),
        "allowed_signers_path": allowed_signers,
        "expected_principal": principal,
        "verification_time_utc": "2026-08-23T12:00:00Z",
    }


def test_accountable_signature_grants_only_additive_denominator_authority(tmp_path: Path):
    verification = verify_denominator_expansion_admission_approval(
        **_signed_fixture(tmp_path)
    )
    assert verification["decision"] == "DENOMINATOR_EXPANSION_ADMISSION_VERIFIED"
    assert verification["counter_authority"] is True
    assert verification["denominator_qualifies"] is True
    assert verification["expected_case_count"] == 1
    assert verification["controls_per_positive"] == 1
    assert verification["maximum_assignable_controls"] == 1
    assert verification["selection_authorized"] is False
    assert verification["qualification_authorized"] is False
    assert verification["stage_promotion_authorized"] is False
    assert verification["recovery3_mutation_authorized"] is False
    assert verification["independent_review_established"] is False


def test_rejects_mechanical_runtime_key_binding(tmp_path: Path):
    values = _signed_fixture(tmp_path)
    binding_path = Path(values["signer_identity_binding_path"])
    binding = json.loads(binding_path.read_text())
    binding["accountable_human_bound"] = False
    binding["mechanical_runtime_key"] = True
    binding["binding_sha256"] = _sha(
        {key: value for key, value in binding.items() if key != "binding_sha256"}
    )
    _write_json(binding_path, binding)
    with pytest.raises(
        ControlDenominatorExpansionAdmissionApprovalError,
        match="identity_binding_not_accountable",
    ):
        verify_denominator_expansion_admission_approval(**values)


def test_rejects_tampered_signature(tmp_path: Path):
    values = _signed_fixture(tmp_path)
    signature = Path(values["signature_path"])
    lines = signature.read_text(encoding="utf-8").splitlines()
    lines[1] = ("A" if lines[1][0] != "A" else "B") + lines[1][1:]
    signature.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(
        ControlDenominatorExpansionAdmissionApprovalError, match="signature_invalid"
    ):
        verify_denominator_expansion_admission_approval(**values)
