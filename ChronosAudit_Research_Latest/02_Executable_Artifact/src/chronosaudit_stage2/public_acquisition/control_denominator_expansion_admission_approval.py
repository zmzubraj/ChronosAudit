from __future__ import annotations

from datetime import datetime
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
import subprocess


class ControlDenominatorExpansionAdmissionApprovalError(ValueError):
    """Raised when accountable expansion-admission authority is invalid."""


SIGNATURE_NAMESPACE = "chronosaudit-stage2-control-denominator-expansion-admission-v1"
_DOWNSTREAM_FALSE = {
    "selection_authorized": False,
    "qualification_authorized": False,
    "stage_promotion_authorized": False,
    "recovery3_mutation_authorized": False,
    "independent_review_established": False,
    "r5_authorized": False,
    "release_authorized": False,
    "publication_authorized": False,
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def canonical_signed_payload(approval: Mapping[str, object]) -> bytes:
    return (_canonical_json(dict(approval)) + "\n").encode("utf-8")


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlDenominatorExpansionAdmissionApprovalError(
            f"{label}_not_ordinary"
        )
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlDenominatorExpansionAdmissionApprovalError(
            f"{label}_missing"
        ) from exc
    if not resolved.is_file():
        raise ControlDenominatorExpansionAdmissionApprovalError(
            f"{label}_not_ordinary"
        )
    return resolved


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlDenominatorExpansionAdmissionApprovalError(
            f"{label}_json_invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise ControlDenominatorExpansionAdmissionApprovalError(
            f"{label}_root_invalid"
        )
    return payload


def _self_hash(payload: Mapping[str, object], field: str, label: str) -> None:
    material = {key: value for key, value in payload.items() if key != field}
    if payload.get(field) != _sha(material):
        raise ControlDenominatorExpansionAdmissionApprovalError(
            f"{label}_self_hash_invalid"
        )


def _time(value: object, label: str) -> datetime:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlDenominatorExpansionAdmissionApprovalError(
            f"{label}_invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.isoformat().replace("+00:00", "Z") != text:
        raise ControlDenominatorExpansionAdmissionApprovalError(
            f"{label}_invalid"
        )
    return parsed


def _fingerprint(public_key: Path) -> str:
    result = subprocess.run(
        ["/usr/bin/ssh-keygen", "-lf", str(public_key), "-E", "sha256"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout.split()) < 2:
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "public_key_invalid"
        )
    return result.stdout.split()[1]


def _validate_projection(
    projection: Mapping[str, object], verification: Mapping[str, object]
) -> None:
    if (
        projection.get("schema_version")
        != "chronosaudit.denominator_expansion_admission_projection.v1"
        or projection.get("decision")
        != "DENOMINATOR_EXPANSION_PROJECTED_NON_AUTHORIZING"
    ):
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "projection_header_invalid"
        )
    _self_hash(projection, "projection_sha256", "projection")
    if (
        projection.get("denominator_qualifies") is not True
        or int(projection.get("maximum_assignable_controls", -1))
        < int(projection.get("target_control_rows", 0))
        or not isinstance(projection.get("admitted_rows"), list)
        or len(projection["admitted_rows"])
        != int(projection.get("admitted_row_count", -1))
    ):
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "projection_not_qualifying"
        )
    for field in (
        "row_admission_authorized",
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
        if projection.get(field) is not False:
            raise ControlDenominatorExpansionAdmissionApprovalError(
                f"projection_{field}_invalid"
            )
    for row in projection["admitted_rows"]:
        if not isinstance(row, Mapping):
            raise ControlDenominatorExpansionAdmissionApprovalError(
                "admitted_row_invalid"
            )
        _self_hash(row, "row_sha256", "admitted_row")
        checks = row.get("checks")
        if not isinstance(checks, Mapping) or len(checks) != 8 or not all(
            value is True for value in checks.values()
        ):
            raise ControlDenominatorExpansionAdmissionApprovalError(
                "admitted_row_checks_invalid"
            )
    if (
        verification.get("schema_version")
        != "chronosaudit.denominator_expansion_admission_projection_verification.v1"
        or verification.get("decision")
        != "DENOMINATOR_EXPANSION_PROJECTION_VERIFIED_NON_AUTHORIZING"
    ):
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "projection_verification_header_invalid"
        )
    _self_hash(verification, "verification_sha256", "projection_verification")
    if (
        verification.get("projection_sha256") != projection.get("projection_sha256")
        or verification.get("combined_denominator_sha256")
        != projection.get("combined_denominator_sha256")
        or verification.get("denominator_qualifies") is not True
        or verification.get("counter_authority") is not False
    ):
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "projection_verification_binding_invalid"
        )


def _validate_identity_binding(
    binding: Mapping[str, object],
    *,
    principal: str,
    public_key: Path,
) -> None:
    if (
        binding.get("schema_version")
        != "chronosaudit.accountable_signer_identity_binding.v1"
        or binding.get("decision") != "ACCOUNTABLE_HUMAN_SIGNER_IDENTITY_BOUND"
        or binding.get("principal") != principal
        or binding.get("authority_scope") != "DENOMINATOR_EXPANSION_ADMISSION_V1"
    ):
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "identity_binding_invalid"
        )
    _self_hash(binding, "binding_sha256", "identity_binding")
    if (
        binding.get("accountable_human_bound") is not True
        or binding.get("mechanical_runtime_key") is not False
        or binding.get("public_key_fingerprint") != _fingerprint(public_key)
    ):
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "identity_binding_not_accountable"
        )
    for field, expected in _DOWNSTREAM_FALSE.items():
        if binding.get(field) is not expected:
            raise ControlDenominatorExpansionAdmissionApprovalError(
                f"identity_binding_{field}_invalid"
            )
    start = _time(binding.get("valid_from_utc"), "identity_valid_from")
    expires = _time(binding.get("expires_at_utc"), "identity_expires_at")
    if start >= expires:
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "identity_validity_window_invalid"
        )


def build_denominator_expansion_admission_approval(
    *,
    projection_path: Path,
    projection_verification_path: Path,
    signer_identity_binding_path: Path,
    signer_public_key_path: Path,
    signer_principal: str,
) -> dict[str, object]:
    """Build the exact payload an accountable human may sign."""
    projection_file = _ordinary(projection_path, "projection")
    verification_file = _ordinary(
        projection_verification_path, "projection_verification"
    )
    binding_file = _ordinary(signer_identity_binding_path, "identity_binding")
    public_key_file = _ordinary(signer_public_key_path, "signer_public_key")
    projection = _load(projection_file, "projection")
    verification = _load(verification_file, "projection_verification")
    _validate_projection(projection, verification)
    principal = signer_principal.strip()
    if not principal:
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "signer_principal_invalid"
        )
    binding = _load(binding_file, "identity_binding")
    _validate_identity_binding(
        binding, principal=principal, public_key=public_key_file
    )
    return {
        "schema_version": "chronosaudit.denominator_expansion_admission_approval.v1",
        "decision": "APPROVE_DENOMINATOR_EXPANSION_ADMISSION",
        "signer_principal": principal,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "valid_from_utc": binding["valid_from_utc"],
        "expires_at_utc": binding["expires_at_utc"],
        "signer_public_key_fingerprint": binding["public_key_fingerprint"],
        "signer_public_key_file_sha256": _file_sha(public_key_file),
        "signer_identity_binding_file_sha256": _file_sha(binding_file),
        "signer_identity_binding_sha256": binding["binding_sha256"],
        "projection_file_sha256": _file_sha(projection_file),
        "projection_sha256": projection["projection_sha256"],
        "projection_verification_file_sha256": _file_sha(verification_file),
        "projection_verification_sha256": verification["verification_sha256"],
        "authorized_denominator_sha256": projection["combined_denominator_sha256"],
        "admitted_rows_sha256": projection["admitted_rows_sha256"],
        "admitted_row_count": projection["admitted_row_count"],
        "expected_case_count": projection["expected_case_count"],
        "controls_per_positive": projection["controls_per_positive"],
        "target_control_rows": projection["target_control_rows"],
        "maximum_assignable_controls": projection["maximum_assignable_controls"],
        "denominator_qualifies": True,
        "row_admission_authorized": True,
        "denominator_admission_authorized": True,
        "counter_authority": True,
        **dict(_DOWNSTREAM_FALSE),
        "authority_limit": "ADDITIVE_CONTROL_INPUT_AUTHORITY_ONLY",
    }


def verify_denominator_expansion_admission_approval(
    *,
    projection_path: Path,
    projection_verification_path: Path,
    signer_identity_binding_path: Path,
    signer_public_key_path: Path,
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
) -> dict[str, object]:
    """Verify accountable authority without promoting any downstream gate."""
    projection_file = _ordinary(projection_path, "projection")
    verification_file = _ordinary(
        projection_verification_path, "projection_verification"
    )
    binding_file = _ordinary(signer_identity_binding_path, "identity_binding")
    public_key_file = _ordinary(signer_public_key_path, "signer_public_key")
    approval_file = _ordinary(approval_path, "approval")
    signature_file = _ordinary(signature_path, "signature")
    signers_file = _ordinary(allowed_signers_path, "allowed_signers")
    expected = build_denominator_expansion_admission_approval(
        projection_path=projection_file,
        projection_verification_path=verification_file,
        signer_identity_binding_path=binding_file,
        signer_public_key_path=public_key_file,
        signer_principal=expected_principal,
    )
    approval = _load(approval_file, "approval")
    if approval != expected:
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "approval_reconstruction_mismatch"
        )
    binding = _load(binding_file, "identity_binding")
    now = _time(verification_time_utc, "verification_time")
    if now < _time(binding["valid_from_utc"], "identity_valid_from"):
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "approval_not_yet_valid"
        )
    if now > _time(binding["expires_at_utc"], "identity_expires_at"):
        raise ControlDenominatorExpansionAdmissionApprovalError("approval_expired")
    result = subprocess.run(
        [
            "/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(signers_file),
            "-I", expected_principal, "-n", SIGNATURE_NAMESPACE,
            "-s", str(signature_file),
        ],
        input=canonical_signed_payload(approval),
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ControlDenominatorExpansionAdmissionApprovalError(
            "signature_invalid"
        )
    output: dict[str, object] = {
        "schema_version": "chronosaudit.denominator_expansion_admission_verification.v1",
        "decision": "DENOMINATOR_EXPANSION_ADMISSION_VERIFIED",
        "signer_principal": expected_principal,
        "signer_public_key_fingerprint": binding["public_key_fingerprint"],
        "signer_identity_binding_sha256": binding["binding_sha256"],
        "approval_file_sha256": _file_sha(approval_file),
        "signature_file_sha256": _file_sha(signature_file),
        "allowed_signers_file_sha256": _file_sha(signers_file),
        "signature_namespace": SIGNATURE_NAMESPACE,
        "projection_sha256": approval["projection_sha256"],
        "projection_verification_sha256": approval[
            "projection_verification_sha256"
        ],
        "authorized_denominator_sha256": approval[
            "authorized_denominator_sha256"
        ],
        "admitted_rows_sha256": approval["admitted_rows_sha256"],
        "admitted_row_count": approval["admitted_row_count"],
        "expected_case_count": approval["expected_case_count"],
        "controls_per_positive": approval["controls_per_positive"],
        "target_control_rows": approval["target_control_rows"],
        "maximum_assignable_controls": approval["maximum_assignable_controls"],
        "denominator_qualifies": True,
        "row_admission_authorized": True,
        "denominator_admission_authorized": True,
        "counter_authority": True,
        **dict(_DOWNSTREAM_FALSE),
        "authority_limit": approval["authority_limit"],
    }
    output["verification_sha256"] = _sha(output)
    return output
