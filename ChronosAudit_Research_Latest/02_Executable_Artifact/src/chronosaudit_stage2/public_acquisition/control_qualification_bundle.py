from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Mapping

from .control_qualification_approval import (
    ControlQualificationApprovalError,
    build_control_qualification_approval_request,
    verify_control_qualification_approval,
)


class ControlQualificationBundleError(ValueError):
    """Raised when a signed control-qualification bundle is not reproducible."""


_SCHEMA = "chronosaudit.control_qualification_bundle.v1"
_FILE_KEYS = {
    "candidate_rows",
    "check_rows",
    "positive_cases",
    "approval",
    "signature",
    "allowed_signers",
    "qualified_controls",
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary_file(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlQualificationBundleError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlQualificationBundleError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlQualificationBundleError(f"{label}_not_ordinary_file")
    return resolved


def _bundle_root(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlQualificationBundleError("bundle_root_symlink_rejected")
    return candidate.resolve(strict=False)


def _relative_to_root(path: Path, root: Path, label: str) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ControlQualificationBundleError(f"{label}_outside_bundle_root") from exc
    if not relative.parts or ".." in relative.parts:
        raise ControlQualificationBundleError(f"{label}_outside_bundle_root")
    return relative.as_posix()


def _resolve_relative(root: Path, value: object, label: str) -> Path:
    text = str(value or "")
    relative = Path(text)
    if not text or relative.is_absolute() or ".." in relative.parts:
        raise ControlQualificationBundleError(f"{label}_path_invalid")
    resolved = (root / relative).resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ControlQualificationBundleError(f"{label}_path_escape") from exc
    return _ordinary_file(resolved, label)


def _file_spec(path: Path, root: Path, label: str, format_name: str) -> dict[str, str]:
    return {
        "path": _relative_to_root(path, root, label),
        "sha256": _sha256_file(path),
        "format": format_name,
    }


def _manifest_sha256(manifest: Mapping[str, object]) -> str:
    return _canonical_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _evidence_inventory(root: Path, evidence_root: Path) -> list[dict[str, str]]:
    evidence_root = _validate_evidence_tree(evidence_root)
    inventory: list[dict[str, str]] = []
    for candidate in sorted(evidence_root.rglob("*")):
        if candidate.is_symlink():
            raise ControlQualificationBundleError("evidence_symlink_rejected")
        if candidate.is_file():
            resolved = candidate.resolve(strict=True)
            inventory.append(
                {
                    "path": _relative_to_root(resolved, root, "evidence_file"),
                    "sha256": _sha256_file(resolved),
                }
            )
    if not inventory:
        raise ControlQualificationBundleError("evidence_inventory_empty")
    return inventory


def _validate_evidence_tree(evidence_root: Path) -> Path:
    candidate = evidence_root.expanduser()
    if candidate.is_symlink():
        raise ControlQualificationBundleError("evidence_root_invalid")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlQualificationBundleError("evidence_root_invalid") from exc
    if not resolved.is_dir():
        raise ControlQualificationBundleError("evidence_root_invalid")
    has_file = False
    for entry in resolved.rglob("*"):
        if entry.is_symlink():
            raise ControlQualificationBundleError("evidence_symlink_rejected")
        if entry.is_file():
            has_file = True
    if not has_file:
        raise ControlQualificationBundleError("evidence_inventory_empty")
    return resolved


def assemble_control_qualification_bundle(
    *,
    bundle_root: Path,
    candidate_rows_path: Path,
    check_rows_path: Path,
    positive_cases_path: Path,
    evidence_root: Path,
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
    expected_positive_rows: int = 417,
    controls_per_positive: int = 10,
) -> dict[str, object]:
    """Copy external signed inputs into a new bundle, then verify the final copy."""
    destination = _bundle_root(bundle_root)
    if destination.exists() or destination.is_symlink():
        raise ControlQualificationBundleError("bundle_root_already_exists")
    sources = {
        "candidates.csv": _ordinary_file(candidate_rows_path, "candidate_rows"),
        "checks.csv": _ordinary_file(check_rows_path, "check_rows"),
        "positive_cases.csv": _ordinary_file(positive_cases_path, "positive_cases"),
        "approval.json": _ordinary_file(approval_path, "approval"),
        "approval.sig": _ordinary_file(signature_path, "signature"),
        "allowed_signers": _ordinary_file(allowed_signers_path, "allowed_signers"),
    }
    source_evidence = _validate_evidence_tree(evidence_root)
    try:
        destination.relative_to(source_evidence)
    except ValueError:
        pass
    else:
        raise ControlQualificationBundleError("bundle_root_inside_evidence_root")

    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent)
    )
    try:
        inputs = staging / "inputs"
        inputs.mkdir()
        for name, source in sources.items():
            shutil.copy2(source, inputs / name)
        shutil.copytree(source_evidence, staging / "evidence")
        built = build_control_qualification_bundle(
            bundle_root=staging,
            candidate_rows_path=inputs / "candidates.csv",
            check_rows_path=inputs / "checks.csv",
            positive_cases_path=inputs / "positive_cases.csv",
            evidence_root=staging / "evidence",
            approval_path=inputs / "approval.json",
            signature_path=inputs / "approval.sig",
            allowed_signers_path=inputs / "allowed_signers",
            expected_principal=expected_principal,
            verification_time_utc=verification_time_utc,
            expected_positive_rows=expected_positive_rows,
            controls_per_positive=controls_per_positive,
        )
        verify_control_qualification_bundle(manifest_path=built["manifest_path"])
        os.replace(staging, destination)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise

    manifest_path = destination / "control_qualification_bundle_manifest.json"
    verified = verify_control_qualification_bundle(manifest_path=manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {
        "manifest_path": manifest_path,
        "projection_path": destination / "qualified_controls.csv",
        "manifest": manifest,
        **verified,
    }


def build_control_qualification_bundle(
    *,
    bundle_root: Path,
    candidate_rows_path: Path,
    check_rows_path: Path,
    positive_cases_path: Path,
    evidence_root: Path,
    approval_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    expected_principal: str,
    verification_time_utc: str,
    expected_positive_rows: int = 417,
    controls_per_positive: int = 10,
) -> dict[str, object]:
    """Build a portable manifest and projection after full signed re-verification."""
    root = _bundle_root(bundle_root)
    files = {
        "candidate_rows": _ordinary_file(candidate_rows_path, "candidate_rows"),
        "check_rows": _ordinary_file(check_rows_path, "check_rows"),
        "positive_cases": _ordinary_file(positive_cases_path, "positive_cases"),
        "approval": _ordinary_file(approval_path, "approval"),
        "signature": _ordinary_file(signature_path, "signature"),
        "allowed_signers": _ordinary_file(allowed_signers_path, "allowed_signers"),
    }
    for label, path in files.items():
        _relative_to_root(path, root, label)
    evidence = evidence_root.expanduser().resolve(strict=True)
    _relative_to_root(evidence, root, "evidence_root")
    request = build_control_qualification_approval_request(
        candidate_rows_path=files["candidate_rows"],
        check_rows_path=files["check_rows"],
        positive_cases_path=files["positive_cases"],
        evidence_root=evidence,
        expected_positive_rows=expected_positive_rows,
        controls_per_positive=controls_per_positive,
    )
    try:
        verified = verify_control_qualification_approval(
            request=request,
            candidate_rows_path=files["candidate_rows"],
            check_rows_path=files["check_rows"],
            positive_cases_path=files["positive_cases"],
            evidence_root=evidence,
            approval_path=files["approval"],
            signature_path=files["signature"],
            allowed_signers_path=files["allowed_signers"],
            expected_principal=expected_principal,
            verification_time_utc=verification_time_utc,
            expected_positive_rows=expected_positive_rows,
            controls_per_positive=controls_per_positive,
        )
    except ControlQualificationApprovalError as exc:
        raise ControlQualificationBundleError(f"approval_verification_failed:{exc}") from exc
    projection_path = root / "qualified_controls.csv"
    manifest_path = root / "control_qualification_bundle_manifest.json"
    projection_bytes = verified["qualified_control_projection"].to_csv(index=False).encode(
        "utf-8"
    )
    if projection_path in files.values() or manifest_path in files.values():
        raise ControlQualificationBundleError("bundle_output_overwrites_input")
    _atomic_write(projection_path, projection_bytes)
    file_specs = {
        "candidate_rows": _file_spec(files["candidate_rows"], root, "candidate_rows", "csv"),
        "check_rows": _file_spec(files["check_rows"], root, "check_rows", "csv"),
        "positive_cases": _file_spec(files["positive_cases"], root, "positive_cases", "csv"),
        "approval": _file_spec(files["approval"], root, "approval", "json"),
        "signature": _file_spec(files["signature"], root, "signature", "openssh-signature"),
        "allowed_signers": _file_spec(files["allowed_signers"], root, "allowed_signers", "openssh-allowed-signers"),
        "qualified_controls": _file_spec(projection_path, root, "qualified_controls", "csv"),
    }
    manifest: dict[str, object] = {
        "schema_version": _SCHEMA,
        "files": file_specs,
        "evidence_root": _relative_to_root(evidence, root, "evidence_root"),
        "evidence_inventory": _evidence_inventory(root, evidence),
        "expected_principal": expected_principal,
        "verification_time_utc": verification_time_utc,
        "expected_positive_rows": expected_positive_rows,
        "controls_per_positive": controls_per_positive,
        "approval_verification_sha256": _canonical_sha256(verified["verification"]),
        "qualified_records_sha256": verified["verification"][
            "qualified_records_sha256"
        ],
        "counter_authority": bool(verified["verification"]["counter_authority"]),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    manifest["manifest_sha256"] = _manifest_sha256(manifest)
    _atomic_write(
        manifest_path,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return {
        "manifest_path": manifest_path,
        "projection_path": projection_path,
        "manifest": manifest,
        **verified,
    }


def verify_control_qualification_bundle(*, manifest_path: Path) -> dict[str, object]:
    """Independently rerun semantic, signature, projection, and inventory checks."""
    manifest_file = _ordinary_file(manifest_path, "manifest")
    root = manifest_file.parent.resolve(strict=True)
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlQualificationBundleError("manifest_json_invalid") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != _SCHEMA:
        raise ControlQualificationBundleError("manifest_schema_invalid")
    if manifest.get("manifest_sha256") != _manifest_sha256(manifest):
        raise ControlQualificationBundleError("manifest_sha256_invalid")
    specs = manifest.get("files")
    if not isinstance(specs, dict) or set(specs) != _FILE_KEYS:
        raise ControlQualificationBundleError("manifest_files_invalid")
    resolved: dict[str, Path] = {}
    for label, spec in specs.items():
        if not isinstance(spec, dict) or set(spec) != {"path", "sha256", "format"}:
            raise ControlQualificationBundleError(f"{label}_spec_invalid")
        path = _resolve_relative(root, spec["path"], label)
        if _sha256_file(path) != spec["sha256"]:
            raise ControlQualificationBundleError(f"{label}_sha256_mismatch")
        resolved[label] = path
    evidence_root_value = manifest.get("evidence_root")
    evidence_relative = Path(str(evidence_root_value or ""))
    if not evidence_root_value or evidence_relative.is_absolute() or ".." in evidence_relative.parts:
        raise ControlQualificationBundleError("evidence_root_path_invalid")
    evidence = (root / evidence_relative).resolve(strict=True)
    try:
        evidence.relative_to(root)
    except ValueError as exc:
        raise ControlQualificationBundleError("evidence_root_path_escape") from exc
    observed_inventory = _evidence_inventory(root, evidence)
    if observed_inventory != manifest.get("evidence_inventory"):
        raise ControlQualificationBundleError("evidence_inventory_mismatch")
    try:
        request = build_control_qualification_approval_request(
            candidate_rows_path=resolved["candidate_rows"],
            check_rows_path=resolved["check_rows"],
            positive_cases_path=resolved["positive_cases"],
            evidence_root=evidence,
            expected_positive_rows=int(manifest["expected_positive_rows"]),
            controls_per_positive=int(manifest["controls_per_positive"]),
        )
        verified = verify_control_qualification_approval(
            request=request,
            candidate_rows_path=resolved["candidate_rows"],
            check_rows_path=resolved["check_rows"],
            positive_cases_path=resolved["positive_cases"],
            evidence_root=evidence,
            approval_path=resolved["approval"],
            signature_path=resolved["signature"],
            allowed_signers_path=resolved["allowed_signers"],
            expected_principal=str(manifest["expected_principal"]),
            verification_time_utc=str(manifest["verification_time_utc"]),
            expected_positive_rows=int(manifest["expected_positive_rows"]),
            controls_per_positive=int(manifest["controls_per_positive"]),
        )
    except (ControlQualificationApprovalError, KeyError, TypeError, ValueError) as exc:
        raise ControlQualificationBundleError(f"bundle_reverification_failed:{exc}") from exc
    if _canonical_sha256(verified["verification"]) != manifest.get(
        "approval_verification_sha256"
    ):
        raise ControlQualificationBundleError("approval_verification_mismatch")
    if verified["verification"]["qualified_records_sha256"] != manifest.get(
        "qualified_records_sha256"
    ):
        raise ControlQualificationBundleError("qualified_records_mismatch")
    regenerated_bytes = verified["qualified_control_projection"].to_csv(
        index=False
    ).encode("utf-8")
    if regenerated_bytes != resolved["qualified_controls"].read_bytes():
        raise ControlQualificationBundleError("qualified_projection_mismatch")
    bundle_verification = {
        **verified["verification"],
        "schema_version": "chronosaudit.control_qualification_bundle_verification.v1",
        "decision": "CONTROL_QUALIFICATION_BUNDLE_VERIFIED",
        "manifest_sha256": manifest["manifest_sha256"],
        "approval_verification_sha256": manifest["approval_verification_sha256"],
        "identity_binding_limit": (
            "KEY_POSSESSION_DOES_NOT_PROVE_REAL_WORLD_AUTHORITY_IDENTITY"
        ),
    }
    return {"bundle_verification": bundle_verification, **verified}
