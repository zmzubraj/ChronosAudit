from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Mapping

from chronosaudit_stage2.public_acquisition.candidate_archive_qualification import (
    _sha256_json,
    build_candidate_archive_run_plan,
)
from chronosaudit_stage2.public_acquisition.historical_snapshot_run import (
    _validate_snapshot_case_envelope_hashes,
)
from chronosaudit_stage2.public_acquisition.strict_snapshot import (
    _load_schema,
    validate_strict_historical_snapshot,
)


REPORT_FILENAME = "candidate_archive_verification_report.json"
PROJECTION_FILENAME = "candidate_archive_verified_projection.csv"
INPUT_MANIFEST_FILENAME = "verification_inputs.json"
CHECKSUM_FILENAME = "SHA256SUMS.txt"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_FIELD_CODE = "secret_like_persisted_field"
_SAFE_METADATA_KEYS = {
    "authorization_basis",
    "cookie_policy",
    "credential_kind",
    "public_endpoint_id",
}
_SECRET_CONTAINER_PATTERNS = (
    ("api", "key"),
    ("token",),
    ("access", "token"),
    ("auth", "token"),
    ("secret",),
    ("client", "secret"),
    ("password",),
    ("private", "key"),
    ("cookie",),
    ("session", "cookie"),
    ("authorization", "header"),
    ("credential",),
    ("credentials",),
)
_PROJECTION_FIELDS = (
    "candidate_id",
    "case_name",
    "chain",
    "input_row_sha256",
    "candidate_envelope_path",
    "candidate_envelope_sha256",
    "historical_case_path",
    "historical_case_sha256",
    "eligible",
    "status",
    "scientific_blockers",
    "run_binding_sha256",
)


def _key_looks_secret_like(key: str) -> bool:
    lowered = key.lower()
    if lowered in _SAFE_METADATA_KEYS or lowered.endswith("sha256"):
        return False
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
    tokens = [token for token in re.split(r"[^a-z0-9]+", normalized) if token]
    if not tokens:
        return False
    for pattern in _SECRET_CONTAINER_PATTERNS:
        width = len(pattern)
        for index in range(len(tokens) - width + 1):
            if tuple(tokens[index:index + width]) == pattern:
                return True
    return False


def _reject_secret_like_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and _key_looks_secret_like(key):
                raise ValueError(_SECRET_FIELD_CODE)
            _reject_secret_like_keys(item)
        return
    if isinstance(value, list):
        for item in value:
            _reject_secret_like_keys(item)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    _reject_secret_like_keys(value)
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    return value


def _case_envelope_hash_valid(payload: Mapping[str, Any]) -> bool:
    body = dict(payload)
    stored = str(body.pop("envelope_sha256", ""))
    return bool(_SHA256.fullmatch(stored)) and stored == _sha256_json(body)


def _safe_existing_file(root: Path, relative: Path, *, code: str) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(code)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(code)
    resolved = current.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(code) from exc
    if not resolved.is_file():
        raise ValueError(code)
    return resolved


def _content_addressed_path(
    run_root: Path,
    *,
    candidate_id: str,
    persisted_path: Any,
    digest: Any,
    category: str,
) -> Path:
    digest_text = str(digest or "").lower()
    if not _SHA256.fullmatch(digest_text):
        raise ValueError("receipt_hash_mismatch")
    expected_relative = Path("receipts") / candidate_id / digest_text[:2] / f"{digest_text}.json"
    persisted = Path(str(persisted_path or ""))
    if tuple(persisted.parts[-4:]) != tuple(expected_relative.parts):
        raise ValueError("receipt_path_escape")
    try:
        path = _safe_existing_file(run_root, expected_relative, code="receipt_path_invalid")
    except ValueError as exc:
        if "invalid" in str(exc):
            raise
        raise ValueError("receipt_path_invalid") from exc
    if _sha256_file(path) != digest_text:
        raise ValueError("receipt_hash_mismatch")
    try:
        payload = _load_json(path)
    except ValueError as exc:
        if str(exc) == _SECRET_FIELD_CODE:
            raise
        raise ValueError("receipt_hash_mismatch") from exc
    except Exception as exc:
        raise ValueError("receipt_hash_mismatch") from exc
    if not isinstance(payload.get("result"), Mapping):
        raise ValueError(f"{category}_response_invalid")
    return path


def _hex_int(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("receipt_response_invalid")
    return int(value, 16)


def _receipt_scientific_blockers(
    run_root: Path,
    *,
    candidate_id: str,
    candidate: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> list[str]:
    observations = list(summary.get("observations") or [])
    blockers: set[str] = set()
    if len(observations) < 2:
        return ["same_family"]
    families = [str(item.get("provider_family") or "") for item in observations if isinstance(item, Mapping)]
    endpoints = [str(item.get("public_endpoint_id") or "") for item in observations if isinstance(item, Mapping)]
    if len(families) != len(observations) or len(set(families)) < 2 or any(not item for item in families):
        blockers.add("same_family")
    if len(endpoints) != len(observations) or len(set(endpoints)) < 2 or any(not item for item in endpoints):
        blockers.add("same_endpoint_identity")

    normalized: list[tuple[int, str, int, int, str]] = []
    for observation in observations:
        if not isinstance(observation, Mapping):
            blockers.add("receipt_header_disagreement")
            continue
        receipt_path = _content_addressed_path(
            run_root,
            candidate_id=candidate_id,
            persisted_path=observation.get("receipt_raw_response_path"),
            digest=observation.get("receipt_response_sha256"),
            category="receipt",
        )
        header_path = _content_addressed_path(
            run_root,
            candidate_id=candidate_id,
            persisted_path=observation.get("header_raw_response_path"),
            digest=observation.get("header_response_sha256"),
            category="header",
        )
        receipt = dict(_load_json(receipt_path)["result"])
        header = dict(_load_json(header_path)["result"])
        try:
            block_number = _hex_int(receipt.get("blockNumber"))
            block_hash = str(receipt.get("blockHash") or "").lower()
            status = _hex_int(receipt.get("status"))
            header_number = _hex_int(header.get("number"))
            header_hash = str(header.get("hash") or "").lower()
        except (TypeError, ValueError):
            blockers.add("receipt_header_disagreement")
            continue
        normalized.append((block_number, block_hash, status, header_number, header_hash))
        if block_number != header_number or block_hash != header_hash:
            blockers.add("receipt_header_disagreement")
    if normalized and len(set(normalized)) != 1:
        blockers.add("receipt_header_disagreement")
    if normalized:
        block_number, block_hash, status, _, _ = normalized[0]
        if block_number != int(summary.get("agreed_block_number") or -1):
            blockers.add("receipt_header_disagreement")
        if block_hash != str(summary.get("agreed_block_hash") or "").lower():
            blockers.add("receipt_header_disagreement")
        if status != int(summary.get("status") if summary.get("status") is not None else -1):
            blockers.add("receipt_header_disagreement")
        if status != 1:
            blockers.add("exploit_transaction_failed")
    if summary.get("proof_sha256") != _sha256_json(
        {
            "normalized": normalized,
            "observations": observations,
        }
    ):
        # Older acquisition code sealed tuple values; canonical JSON treats them as arrays.
        blockers.add("receipt_proof_hash_mismatch")
    return sorted(blockers)


def _historical_case_blockers(
    run_root: Path,
    *,
    candidate_id: str,
    expected_sha256: str,
) -> tuple[list[str], str, str]:
    relative = Path("historical_cases") / candidate_id / f"{candidate_id}.json"
    path = _safe_existing_file(run_root, relative, code="historical_case_path_invalid")
    payload = _load_json(path)
    runtime_result = dict(payload)
    runtime_result.update(
        {"resumed": False, "quarantined": False, "quarantine_reason": None}
    )
    if expected_sha256 != _sha256_json(runtime_result):
        raise ValueError("historical_case_hash_mismatch")
    if not _validate_snapshot_case_envelope_hashes(payload):
        raise ValueError("historical_case_hash_mismatch")
    if str(payload.get("case_id") or "") != candidate_id:
        raise ValueError("historical_case_binding_mismatch")
    strict = dict(payload.get("strict_snapshot") or {})
    receipt_root = run_root / "historical_cases" / candidate_id / "receipts"
    validation = validate_strict_historical_snapshot(
        strict,
        schema=_load_schema("strict_historical_snapshot.schema.json"),
        receipt_root=receipt_root,
        provider_identity=dict(strict.get("provider_identity") or {}),
    )
    blockers = list(validation.errors)
    if payload.get("strict_snapshot_closed") is not True or strict.get("strict_snapshot_closed") is not True:
        blockers.extend(str(item) for item in (payload.get("blockers") or strict.get("blockers") or ["strict_snapshot_partial"]))
    return sorted(set(blockers)), relative.as_posix(), _sha256_file(path)


def _row_for_case(
    run_root: Path,
    *,
    expected: Mapping[str, Any],
    persisted: Mapping[str, Any],
    binding_sha256: str,
) -> tuple[dict[str, Any], list[str]]:
    candidate_id = str(expected["candidate_id"])
    relative = Path("cases") / f"{candidate_id}.json"
    path = _safe_existing_file(run_root, relative, code="candidate_case_path_invalid")
    file_payload = _load_json(path)
    if dict(persisted) != file_payload:
        raise ValueError("qualification_result_case_mismatch")
    if not _case_envelope_hash_valid(file_payload):
        raise ValueError("candidate_case_hash_mismatch")
    if file_payload.get("schema_version") != "candidate_archive_case.v1":
        raise ValueError("candidate_case_schema_invalid")
    if file_payload.get("candidate_id") != candidate_id:
        raise ValueError("candidate_case_binding_mismatch")
    if file_payload.get("run_binding_sha256") != binding_sha256:
        raise ValueError("candidate_case_binding_mismatch")
    candidate = dict(file_payload.get("candidate_input") or {})
    if candidate != dict(expected) or file_payload.get("candidate_input_sha256") != _sha256_json(candidate):
        raise ValueError("candidate_input_mismatch")

    blockers: set[str] = set(str(item) for item in (file_payload.get("blockers") or []) if str(item))
    summary = dict(file_payload.get("receipt_summary") or {})
    historical_path = ""
    historical_file_sha = ""
    if summary:
        blockers.update(
            _receipt_scientific_blockers(
                run_root,
                candidate_id=candidate_id,
                candidate=candidate,
                summary=summary,
            )
        )
    if file_payload.get("historical_case_sha256"):
        historical_blockers, historical_path, historical_file_sha = _historical_case_blockers(
            run_root,
            candidate_id=candidate_id,
            expected_sha256=str(file_payload["historical_case_sha256"]),
        )
        blockers.update(historical_blockers)
    elif file_payload.get("qualified") is True:
        raise ValueError("historical_case_missing")

    eligible = bool(
        not blockers
        and summary
        and historical_path
        and file_payload.get("qualification_closed") is True
        and file_payload.get("status") == "VERIFIED"
    )
    row = {
        "candidate_id": candidate_id,
        "case_name": str(candidate.get("case_name") or ""),
        "chain": str(candidate.get("chain") or ""),
        "input_row_sha256": str(candidate.get("input_row_sha256") or ""),
        "candidate_envelope_path": relative.as_posix(),
        "candidate_envelope_sha256": str(file_payload.get("envelope_sha256") or ""),
        "historical_case_path": historical_path,
        "historical_case_sha256": historical_file_sha,
        "eligible": eligible,
        "status": "VERIFIED" if eligible else "PARTIAL",
        "scientific_blockers": sorted(blockers),
        "run_binding_sha256": binding_sha256,
    }
    return row, sorted(blockers)


def _write_outputs(
    output_dir: Path,
    *,
    report: dict[str, Any],
    projection_rows: list[dict[str, Any]],
    input_manifest: dict[str, Any],
) -> None:
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    try:
        (stage / REPORT_FILENAME).write_bytes(_canonical_json(report) + b"\n")
        with (stage / PROJECTION_FILENAME).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(_PROJECTION_FIELDS))
            writer.writeheader()
            for row in projection_rows:
                encoded = dict(row)
                encoded["eligible"] = "true" if row["eligible"] else "false"
                encoded["scientific_blockers"] = json.dumps(row["scientific_blockers"], separators=(",", ":"))
                writer.writerow(encoded)
        (stage / INPUT_MANIFEST_FILENAME).write_bytes(_canonical_json(input_manifest) + b"\n")
        checksum_lines = [
            f"{_sha256_file(stage / name)}  {name}"
            for name in (REPORT_FILENAME, PROJECTION_FILENAME, INPUT_MANIFEST_FILENAME)
        ]
        (stage / CHECKSUM_FILENAME).write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
        if output_dir.exists():
            if any(output_dir.iterdir()):
                raise ValueError("verification_output_exists")
            output_dir.rmdir()
        os.replace(stage, output_dir)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def verify_candidate_archive_run(
    *,
    run_root: str | Path,
    revision_root: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    run = Path(run_root).expanduser().resolve()
    revision = Path(revision_root).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve(strict=False)
    integrity_errors: list[str] = []

    try:
        plan = build_candidate_archive_run_plan(revision)
    except Exception:
        plan = {"ordered_candidates": [], "revision_input_hashes": {}}
        integrity_errors.append("cohort_revision_invalid")
    expected_candidates = list(plan.get("ordered_candidates") or [])
    expected_by_id = {str(item["candidate_id"]): dict(item) for item in expected_candidates}

    try:
        manifest = _load_json(_safe_existing_file(run, Path("run_manifest.json"), code="run_manifest_invalid"))
    except ValueError as exc:
        manifest = {}
        integrity_errors.append(str(exc))
    except Exception:
        manifest = {}
        integrity_errors.append("run_manifest_invalid")
    manifest_body = dict(manifest)
    stored_binding = str(manifest_body.pop("binding_sha256", ""))
    if not _SHA256.fullmatch(stored_binding) or stored_binding != _sha256_json(manifest_body):
        integrity_errors.append("run_manifest_binding_hash_mismatch")
    if manifest.get("schema_version") != "candidate_archive_run.v1":
        integrity_errors.append("run_manifest_schema_invalid")
    if manifest.get("revision_input_hashes") != plan.get("revision_input_hashes"):
        integrity_errors.append("run_manifest_revision_hashes_mismatch")

    try:
        result_path = _safe_existing_file(run, Path("qualification_result.json"), code="qualification_result_invalid")
        result = _load_json(result_path)
    except ValueError as exc:
        result = {}
        integrity_errors.append(str(exc))
    except Exception:
        result = {}
        integrity_errors.append("qualification_result_invalid")
    if result.get("schema_version") != "candidate_archive_qualification_result.v1":
        integrity_errors.append("qualification_result_schema_invalid")
    if result.get("binding_sha256") != stored_binding:
        integrity_errors.append("qualification_result_binding_mismatch")
    persisted_cases = list(result.get("cases") or [])
    persisted_ids = [str(item.get("candidate_id") or "") for item in persisted_cases if isinstance(item, Mapping)]
    expected_ids = [str(item["candidate_id"]) for item in expected_candidates]
    if (
        len(persisted_cases) != len(expected_candidates)
        or len(set(persisted_ids)) != len(persisted_ids)
        or set(persisted_ids) != set(expected_ids)
        or int(result.get("candidate_count") or -1) != len(persisted_cases)
    ):
        integrity_errors.append("candidate_population_mismatch")

    rows: list[dict[str, Any]] = []
    persisted_by_id = {
        str(item.get("candidate_id") or ""): dict(item)
        for item in persisted_cases
        if isinstance(item, Mapping) and str(item.get("candidate_id") or "") in expected_by_id
    }
    for expected in expected_candidates:
        candidate_id = str(expected["candidate_id"])
        persisted = persisted_by_id.get(candidate_id)
        if persisted is None:
            rows.append({
                "candidate_id": candidate_id,
                "case_name": str(expected.get("case_name") or ""),
                "chain": str(expected.get("chain") or ""),
                "input_row_sha256": str(expected.get("input_row_sha256") or ""),
                "candidate_envelope_path": "",
                "candidate_envelope_sha256": "",
                "historical_case_path": "",
                "historical_case_sha256": "",
                "eligible": False,
                "status": "PARTIAL",
                "scientific_blockers": ["candidate_result_missing"],
                "run_binding_sha256": stored_binding,
            })
            continue
        try:
            row, _ = _row_for_case(
                run,
                expected=expected,
                persisted=persisted,
                binding_sha256=stored_binding,
            )
        except ValueError as exc:
            code = str(exc)
            if code not in integrity_errors:
                integrity_errors.append(code)
            row = {
                "candidate_id": candidate_id,
                "case_name": str(expected.get("case_name") or ""),
                "chain": str(expected.get("chain") or ""),
                "input_row_sha256": str(expected.get("input_row_sha256") or ""),
                "candidate_envelope_path": f"cases/{candidate_id}.json",
                "candidate_envelope_sha256": "",
                "historical_case_path": "",
                "historical_case_sha256": "",
                "eligible": False,
                "status": "PARTIAL",
                "scientific_blockers": [],
                "run_binding_sha256": stored_binding,
            }
        rows.append(row)

    if integrity_errors:
        for row in rows:
            row["eligible"] = False
            row["status"] = "PARTIAL"
    rows.sort(key=lambda item: (item["chain"], expected_ids.index(item["candidate_id"])))
    eligible_rows = [row for row in rows if row["eligible"]]
    chain_counts = {
        chain: sum(1 for row in eligible_rows if row["chain"] == chain)
        for chain in sorted({row["chain"] for row in rows})
    }
    report: dict[str, Any] = {
        "schema_version": "candidate_archive_verification_report.v1",
        "candidate_count": len(rows),
        "eligible_count": len(eligible_rows),
        "eligible_chain_counts": chain_counts,
        "counter_authority": not bool(integrity_errors),
        "integrity_errors": sorted(set(integrity_errors)),
        "rows": rows,
        "authoritative_input_hashes": {
            "run_manifest_sha256": _sha256_file(run / "run_manifest.json") if (run / "run_manifest.json").is_file() else "",
            "qualification_result_sha256": _sha256_file(run / "qualification_result.json") if (run / "qualification_result.json").is_file() else "",
            "run_binding_sha256": stored_binding,
            "revision_input_hashes": dict(plan.get("revision_input_hashes") or {}),
        },
    }
    report["report_sha256"] = _sha256_json(report)
    input_manifest = {
        "schema_version": "candidate_archive_verification_inputs.v1",
        **report["authoritative_input_hashes"],
    }
    _write_outputs(output, report=report, projection_rows=rows, input_manifest=input_manifest)
    return report


__all__ = ["verify_candidate_archive_run"]
