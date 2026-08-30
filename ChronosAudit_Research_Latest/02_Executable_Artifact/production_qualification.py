from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import os
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.counters import (  # noqa: E402
    COUNTER_ARTIFACT_VERSION,
    CORE_COUNTER_KEYS,
    COUNTER_TARGET_KEYS,
    DEFAULT_COUNTER_TARGETS,
    PACKET_COUNTER_KEYS,
    build_counter_artifact,
    canonical_manifest_sha256,
    overlay_historical_snapshot_projection,
    HISTORICAL_SNAPSHOT_OVERLAY_FIELDS,
    validate_counter_artifact,
)
from chronosaudit_stage2.public_acquisition.historical_snapshot_verifier import (  # noqa: E402
    PROJECTION_FIELDS as HISTORICAL_PROJECTION_FIELDS,
    PROJECTION_FILENAME as HISTORICAL_PROJECTION_FILENAME,
    REPORT_FILENAME as HISTORICAL_REPORT_FILENAME,
    verify_historical_snapshot_run,
)
from chronosaudit_stage2.public_acquisition.control_qualification_bundle import (  # noqa: E402
    ControlQualificationBundleError,
    verify_control_qualification_bundle,
)

COUNTER_ARTIFACT_PATH = Path(os.getenv("CHRONOS_COUNTER_ARTIFACT_PATH", ROOT / "reports" / "public_acquisition_counters.json"))
COUNTER_INPUT_MANIFEST_PATH = Path(os.getenv("CHRONOS_COUNTER_INPUT_MANIFEST_PATH", ROOT / "reports" / "public_acquisition_counter_inputs.json"))
OUTPUT_PATH = Path(os.getenv("CHRONOS_PRODUCTION_QUALIFICATION_OUTPUT_PATH", ROOT / "reports" / "production_qualification.json"))
REQUIRED_MANIFEST_INPUT_KEYS = (
    "positive_cases",
    "deployment_denominator",
    "control_rows",
    "positive_case_review_packets",
    "control_review_packets",
    "finalized_positive_adjudications",
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_json_value(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_csv_value(path: Path):
    pandas = __import__("pandas")
    try:
        return pandas.read_csv(path)
    except pandas.errors.EmptyDataError:
        return pandas.DataFrame()


def _project_manifest_positive_cases(frame):
    runner_path = ROOT / "run_public_evidence_acquisition.py"
    spec = importlib.util.spec_from_file_location("production_qualification_runner", runner_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load runner module from {runner_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module._projectable_positive_cases(frame)


def _input_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def validate_counter_input_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []
    allowed_keys = {"artifact_schema_version", "inputs", "minimum_independent_r5_blocks", "counter_targets", "input_manifest_sha256", "historical_snapshot_verification", "control_qualification_bundle"}
    unexpected_keys = sorted(set(manifest.keys()) - allowed_keys)
    if unexpected_keys:
        errors.append(f"unexpected_manifest_keys:{','.join(unexpected_keys)}")
    historical = manifest.get("historical_snapshot_verification")
    if historical is not None:
        if not isinstance(historical, dict):
            errors.append("invalid_historical_snapshot_verification")
        else:
            required = {"run_root", "report", "projection", "observed", "required", "counter_authority"}
            if set(historical) != required:
                errors.append("invalid_historical_snapshot_verification_keys")
            for key in ("report", "projection"):
                spec = historical.get(key)
                if not isinstance(spec, dict) or set(spec) != {"path", "sha256", "format"}:
                    errors.append(f"invalid_historical_snapshot_{key}")
    control_qualification = manifest.get("control_qualification_bundle")
    if control_qualification is not None:
        if (
            not isinstance(control_qualification, dict)
            or set(control_qualification) != {"manifest", "counter_authority"}
            or control_qualification.get("counter_authority") is not True
            or not isinstance(control_qualification.get("manifest"), dict)
            or set(control_qualification["manifest"]) != {"path", "sha256", "format"}
            or control_qualification["manifest"].get("format") != "json"
        ):
            errors.append("invalid_control_qualification_bundle")
    if manifest.get("artifact_schema_version") != COUNTER_ARTIFACT_VERSION:
        errors.append("invalid_manifest_schema_version")
    counter_targets = manifest.get("counter_targets")
    if not isinstance(counter_targets, dict):
        errors.append("missing_counter_targets")
    else:
        normalized_targets: dict[str, object] | None = None
        missing_target_keys = sorted(set(COUNTER_TARGET_KEYS) - set(counter_targets.keys()))
        unexpected_target_keys = sorted(set(counter_targets.keys()) - set(COUNTER_TARGET_KEYS))
        if missing_target_keys:
            errors.append(f"missing_counter_target_keys:{','.join(missing_target_keys)}")
        if unexpected_target_keys:
            errors.append(f"unexpected_counter_target_keys:{','.join(unexpected_target_keys)}")
        per_chain = counter_targets.get("deployment_denominator_per_chain")
        expected_chain_keys = set(DEFAULT_COUNTER_TARGETS["deployment_denominator_per_chain"].keys())
        if not isinstance(per_chain, dict):
            errors.append("invalid_deployment_denominator_per_chain")
        else:
            missing_chain_keys = sorted(expected_chain_keys - set(per_chain.keys()))
            unexpected_chain_keys = sorted(set(per_chain.keys()) - expected_chain_keys)
            if missing_chain_keys:
                errors.append(f"missing_deployment_denominator_per_chain_keys:{','.join(missing_chain_keys)}")
            if unexpected_chain_keys:
                errors.append(f"unexpected_deployment_denominator_per_chain_keys:{','.join(unexpected_chain_keys)}")
        for key in (
            "deployment_denominator_required",
            "control_candidates_required",
            "qualified_controls_required",
            "independent_r5_blocks_required",
        ):
            if key in counter_targets:
                try:
                    if int(counter_targets[key]) < 0:
                        errors.append(f"invalid_counter_target_value:{key}")
                except (TypeError, ValueError):
                    errors.append(f"invalid_counter_target_value:{key}")
        if isinstance(per_chain, dict):
            for chain in expected_chain_keys.intersection(per_chain.keys()):
                try:
                    if int(per_chain[chain]) < 0:
                        errors.append(f"invalid_deployment_denominator_per_chain_value:{chain}")
                except (TypeError, ValueError):
                    errors.append(f"invalid_deployment_denominator_per_chain_value:{chain}")
        if not errors:
            canonical_targets = {
                "deployment_denominator_required": int(DEFAULT_COUNTER_TARGETS["deployment_denominator_required"]),
                "deployment_denominator_per_chain": {
                    chain: int(DEFAULT_COUNTER_TARGETS["deployment_denominator_per_chain"][chain])
                    for chain in sorted(expected_chain_keys)
                },
                "control_candidates_required": int(DEFAULT_COUNTER_TARGETS["control_candidates_required"]),
                "qualified_controls_required": int(DEFAULT_COUNTER_TARGETS["qualified_controls_required"]),
                "independent_r5_blocks_required": int(DEFAULT_COUNTER_TARGETS["independent_r5_blocks_required"]),
            }
            normalized_targets = {
                "deployment_denominator_required": int(counter_targets["deployment_denominator_required"]),
                "deployment_denominator_per_chain": {
                    chain: int(per_chain[chain])
                    for chain in sorted(expected_chain_keys)
                },
                "control_candidates_required": int(counter_targets["control_candidates_required"]),
                "qualified_controls_required": int(counter_targets["qualified_controls_required"]),
                "independent_r5_blocks_required": int(counter_targets["independent_r5_blocks_required"]),
            }
            if normalized_targets != canonical_targets:
                errors.append("counter_targets_canonical_mismatch")
        try:
            manifest_r5 = int(manifest.get("minimum_independent_r5_blocks", 120))
        except (TypeError, ValueError):
            errors.append("invalid_minimum_independent_r5_blocks")
        else:
            if normalized_targets is not None and manifest_r5 != normalized_targets["independent_r5_blocks_required"]:
                errors.append("minimum_independent_r5_blocks_target_mismatch")
    if "inputs" not in manifest or not isinstance(manifest["inputs"], dict):
        errors.append("missing_manifest_inputs")
        return errors
    input_keys = set(manifest["inputs"].keys())
    missing_inputs = sorted(set(REQUIRED_MANIFEST_INPUT_KEYS) - input_keys)
    unexpected_inputs = sorted(input_keys - set(REQUIRED_MANIFEST_INPUT_KEYS))
    if missing_inputs:
        errors.append(f"missing_manifest_inputs:{','.join(missing_inputs)}")
    if unexpected_inputs:
        errors.append(f"unexpected_manifest_inputs:{','.join(unexpected_inputs)}")
    if canonical_manifest_sha256(manifest) != manifest.get("input_manifest_sha256"):
        errors.append("manifest_sha256_mismatch")
    for input_key in REQUIRED_MANIFEST_INPUT_KEYS:
        spec = manifest["inputs"].get(input_key)
        if not isinstance(spec, dict):
            errors.append(f"invalid_manifest_input_spec:{input_key}")
            continue
        if set(spec.keys()) != {"path", "sha256", "format"}:
            errors.append(f"invalid_manifest_input_keys:{input_key}")
            continue
        if not isinstance(spec["path"], str) or not spec["path"]:
            errors.append(f"invalid_manifest_input_path:{input_key}")
        if not isinstance(spec["sha256"], str) or len(spec["sha256"]) != 64:
            errors.append(f"invalid_manifest_input_sha256:{input_key}")
        if spec["format"] not in {"csv", "json"}:
            errors.append(f"invalid_manifest_input_format:{input_key}")
    return errors


def _manifest_input_root(manifest_path: Path) -> Path:
    resolved = manifest_path.resolve(strict=False)
    parts = resolved.parts
    for index in range(len(parts) - 1):
        if parts[index : index + 2] == ("reports", "public_acquisition"):
            return Path(*parts[:index])
    return resolved.parent


def _resolve_manifest_input_path(manifest_path: Path, candidate: str) -> Path:
    path = Path(candidate)
    if path.is_absolute():
        return path.resolve(strict=False)
    input_root = _manifest_input_root(manifest_path)
    resolved = (input_root / path).resolve(strict=False)
    try:
        resolved.relative_to(input_root)
    except ValueError as exc:
        raise ValueError(f"manifest input path escapes input root: {candidate}") from exc
    return resolved


def load_verified_control_qualification_bundle(
    manifest: dict,
    *,
    manifest_path: Path,
):
    binding = manifest.get("control_qualification_bundle")
    if not isinstance(binding, dict) or binding.get("counter_authority") is not True:
        raise ValueError("control_qualification_bundle_missing_or_unauthorized")
    spec = binding.get("manifest")
    if (
        not isinstance(spec, dict)
        or set(spec) != {"path", "sha256", "format"}
        or spec.get("format") != "json"
    ):
        raise ValueError("control_qualification_bundle_manifest_spec_invalid")
    bundle_path = _resolve_manifest_input_path(manifest_path, spec["path"])
    if not bundle_path.exists() or bundle_path.is_symlink():
        raise ValueError("control_qualification_bundle_manifest_missing")
    if _input_file_sha256(bundle_path) != spec["sha256"]:
        raise ValueError("control_qualification_bundle_manifest_sha256_mismatch")
    try:
        result = verify_control_qualification_bundle(manifest_path=bundle_path)
    except ControlQualificationBundleError as exc:
        raise ValueError(f"control_qualification_bundle_verification_failed:{exc}") from exc
    verification = result["bundle_verification"]
    if verification.get("counter_authority") is not True:
        raise ValueError("control_qualification_bundle_counter_authority_invalid")
    return result["qualified_control_projection"], verification


def _load_evidence_from_manifest(manifest: dict, *, manifest_path: Path) -> tuple[dict[str, object], list[str]]:
    pandas = __import__("pandas")
    errors: list[str] = []
    evidence: dict[str, object] = {
        "minimum_independent_r5_blocks": int(manifest.get("minimum_independent_r5_blocks", 120)),
        "counter_targets": manifest.get("counter_targets"),
    }
    for input_key in REQUIRED_MANIFEST_INPUT_KEYS:
        spec = manifest["inputs"][input_key]
        try:
            path = _resolve_manifest_input_path(manifest_path, spec["path"])
        except ValueError:
            errors.append(f"input_file_path_escape:{input_key}")
            continue
        if not path.exists():
            errors.append(f"missing_input_file:{input_key}")
            continue
        if _input_file_sha256(path) != spec["sha256"]:
            errors.append(f"input_file_sha256_mismatch:{input_key}")
            continue
        try:
            if spec["format"] == "csv":
                frame = _load_csv_value(path)
                evidence[input_key] = _project_manifest_positive_cases(frame) if input_key == "positive_cases" else frame
            else:
                evidence[input_key] = _load_json_value(path)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            pandas.errors.EmptyDataError,
            pandas.errors.ParserError,
            ValueError,
            TypeError,
            AttributeError,
        ) as exc:
            errors.append(f"input_file_parse_error:{input_key}:{type(exc).__name__}")
    qualification_binding = manifest.get("control_qualification_bundle")
    if isinstance(qualification_binding, dict):
        try:
            projection, verification = load_verified_control_qualification_bundle(
                manifest, manifest_path=manifest_path
            )
            observed_controls = evidence.get("control_rows")
            if observed_controls is None:
                errors.append("control_qualification_bundle_control_rows_missing")
            else:
                left = observed_controls.astype("object").where(
                    pandas.notna(observed_controls), ""
                ).astype(str)
                right = projection.astype("object").where(
                    pandas.notna(projection), ""
                ).astype(str)
                if list(left.columns) != list(right.columns) or not left.equals(right):
                    errors.append("control_qualification_bundle_projection_mismatch")
                else:
                    evidence["control_qualification_verification"] = verification
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            errors.append(
                "control_qualification_bundle_parse_error:"
                + type(exc).__name__
            )
    if not errors and manifest.get("historical_snapshot_verification") is not None:
        try:
            projection = load_verified_historical_projection(manifest, manifest_path=manifest_path)
            evidence["positive_cases"] = overlay_historical_snapshot_projection(
                evidence["positive_cases"],
                projection,
            )
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            errors.append(f"historical_snapshot_verification_error:{type(exc).__name__}")
    return evidence, errors


def _output_root_from_manifest_path(manifest_path: Path) -> Path:
    resolved = manifest_path.resolve(strict=False)
    parts = resolved.parts
    try:
        index = len(parts) - 1 - list(reversed(parts)).index("reports")
    except ValueError as exc:
        raise ValueError("historical_snapshot_manifest_root_invalid") from exc
    return Path(*parts[:index])


def _contained_path(root: Path, relative: str, *, code: str) -> Path:
    candidate = Path(str(relative))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(code)
    joined = root / candidate
    cursor = joined
    while cursor != root and cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError(code)
        cursor = cursor.parent
    resolved = joined.resolve(strict=False)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(code) from exc
    return resolved


def load_verified_historical_projection(manifest: dict, *, manifest_path: Path):
    pandas = __import__("pandas")
    binding = manifest.get("historical_snapshot_verification")
    if not isinstance(binding, dict) or binding.get("counter_authority") is not True:
        raise ValueError("historical_snapshot_binding_invalid")
    output_root = _output_root_from_manifest_path(manifest_path)
    historical_root = _contained_path(output_root, binding["run_root"], code="historical_snapshot_run_root_invalid")
    report_copy = _contained_path(output_root, binding["report"]["path"], code="historical_snapshot_report_path_invalid")
    projection_copy = _contained_path(output_root, binding["projection"]["path"], code="historical_snapshot_projection_path_invalid")
    for label, path, spec in (
        ("report", report_copy, binding["report"]),
        ("projection", projection_copy, binding["projection"]),
    ):
        if path.is_symlink() or not path.is_file() or _input_file_sha256(path) != spec["sha256"]:
            raise ValueError(f"historical_snapshot_{label}_binding_invalid")
    with tempfile.TemporaryDirectory(prefix="chronos-historical-reverify-") as temp_dir:
        report = verify_historical_snapshot_run(historical_root, output_path=Path(temp_dir))
        if report.get("counter_authority") is not True or report.get("integrity_errors"):
            raise ValueError("historical_snapshot_reverification_failed")
        regenerated_report = Path(temp_dir) / HISTORICAL_REPORT_FILENAME
        regenerated_projection = Path(temp_dir) / HISTORICAL_PROJECTION_FILENAME
        if regenerated_report.read_bytes() != report_copy.read_bytes():
            raise ValueError("historical_snapshot_report_mismatch")
        if regenerated_projection.read_bytes() != projection_copy.read_bytes():
            raise ValueError("historical_snapshot_projection_mismatch")
    projection = pandas.read_csv(projection_copy, keep_default_na=False)
    if len(projection) != 417 or int(binding.get("required") or 0) != 417:
        raise ValueError("historical_snapshot_projection_cardinality_mismatch")
    if list(projection.columns) != HISTORICAL_PROJECTION_FIELDS:
        raise ValueError("historical_snapshot_projection_schema_mismatch")
    if int(binding.get("observed") or -1) != int(report.get("observed") or 0):
        raise ValueError("historical_snapshot_observed_mismatch")
    return projection[["case_id", "case_name", *HISTORICAL_SNAPSHOT_OVERLAY_FIELDS]]


def _fail_closed_payload(*, reason: str, details: dict | None = None) -> dict:
    return {
        "qualified": False,
        "checks": [
            {
                "gate": "canonical public acquisition counter artifact",
                "required": COUNTER_ARTIFACT_VERSION,
                "observed": details or {},
                "passed": False,
            }
        ],
        "artifact_schema_version": None,
        "counter_input_manifest_errors": [],
        "counter_artifact_errors": [],
        "production_qualification_exit": 3,
        "qualification_semantics": reason,
    }


def _load_root_json_with_fail_closed(
    *,
    path: Path,
    error_prefix: str,
    reason: str,
) -> tuple[dict | None, dict | None]:
    try:
        payload = _load_json(path)
        if not isinstance(payload, dict):
            raise ValueError("root JSON payload must be an object")
        return payload, None
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        error_name = "RootJsonTypeError" if exc.__class__ is ValueError else type(exc).__name__
        payload = _fail_closed_payload(
            reason=reason,
            details={
                "path": str(path),
                "error": error_name,
            },
        )
        payload_key = (
            "counter_input_manifest_errors"
            if error_prefix == "counter_input_manifest_parse_error"
            else "counter_artifact_errors"
        )
        payload[payload_key] = [f"{error_prefix}:{error_name}"]
        return None, payload


def evaluate_production_qualification(
    *,
    counter_artifact_path: Path | None = None,
    counter_input_manifest_path: Path | None = None,
) -> dict:
    artifact_path = counter_artifact_path or COUNTER_ARTIFACT_PATH
    manifest_path = counter_input_manifest_path or COUNTER_INPUT_MANIFEST_PATH
    if not manifest_path.exists():
        return _fail_closed_payload(
            reason="fail_closed_missing_counter_input_manifest",
            details={"missing_path": str(manifest_path)},
        )
    if not artifact_path.exists():
        return _fail_closed_payload(
            reason="fail_closed_missing_counter_artifact",
            details={"missing_path": str(artifact_path)},
        )

    manifest, manifest_failure = _load_root_json_with_fail_closed(
        path=manifest_path,
        error_prefix="counter_input_manifest_parse_error",
        reason="fail_closed_counter_input_manifest_parse_error",
    )
    if manifest_failure is not None:
        return manifest_failure

    artifact, artifact_failure = _load_root_json_with_fail_closed(
        path=artifact_path,
        error_prefix="counter_artifact_parse_error",
        reason="fail_closed_counter_artifact_parse_error",
    )
    if artifact_failure is not None:
        return artifact_failure

    assert manifest is not None
    assert artifact is not None
    manifest_errors = validate_counter_input_manifest(manifest)
    errors = list(manifest_errors)
    errors.extend(validate_counter_artifact(artifact))
    if artifact.get("input_manifest_sha256") != manifest.get("input_manifest_sha256"):
        errors.append("input_manifest_sha256_mismatch")
    if not manifest_errors:
        evidence, input_errors = _load_evidence_from_manifest(manifest, manifest_path=manifest_path)
        errors.extend(input_errors)
        if not errors and not input_errors:
            try:
                regenerated = build_counter_artifact(
                    evidence,
                    input_manifest_sha256=manifest["input_manifest_sha256"],
                )
            except (TypeError, ValueError) as exc:
                errors.append(f"counter_projection_error:{exc}")
            else:
                if regenerated["counters"] != artifact.get("counters", {}):
                    errors.append("counter_projection_mismatch")

    counters = artifact.get("counters", {})
    checks = []
    for key in (*CORE_COUNTER_KEYS[:-1], *PACKET_COUNTER_KEYS):
        checks.append(
            {
                "gate": key,
                "required": counters.get(key, {}).get("required"),
                "observed": counters.get(key, {}).get("observed"),
                "passed": bool(counters.get(key, {}).get("passed", False)),
            }
        )
    checks.append(
        {
            "gate": "release_eligible_cases",
            "required": ">0 after full case-level conjunction",
            "observed": counters.get("release_eligible_cases", 0),
            "passed": bool(counters.get("release_eligible_cases", 0) > 0),
        }
    )
    qualified = not errors and all(check["passed"] for check in checks)
    return {
        "qualified": qualified,
        "checks": checks,
        "artifact_schema_version": artifact.get("artifact_schema_version"),
        "counter_input_manifest_errors": manifest_errors,
        "counter_artifact_errors": errors,
        "production_qualification_exit": 0 if qualified else 3,
        "qualification_semantics": "operational evidence required; packets, env counts, AI review, unhashed inputs, and self-reported digests never satisfy live gates",
    }


def main() -> None:
    result = evaluate_production_qualification()

    OUTPUT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(result["production_qualification_exit"])


if __name__ == "__main__":
    main()
