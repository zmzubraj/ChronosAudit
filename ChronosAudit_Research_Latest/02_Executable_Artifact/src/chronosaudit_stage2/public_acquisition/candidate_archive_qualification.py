from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Mapping


_TX = __import__("re").compile(r"^0x[0-9a-f]{64}$")
_ADDRESS = __import__("re").compile(r"^0x[0-9a-f]{40}$")
_SHA256 = __import__("re").compile(r"^[0-9a-f]{64}$")
_REQUIRED_REVISION_FILES = (
    "revision_plan.json",
    "screened_candidates.csv",
    "replacement_slots.csv",
    "slot_candidate_order.csv",
    "provenance.json",
    "screening_log.json",
    "SHA256SUMS.txt",
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seal_case_envelope(payload: Mapping[str, Any]) -> dict[str, Any]:
    sealed = dict(payload)
    sealed.pop("envelope_sha256", None)
    sealed["envelope_sha256"] = _sha256_json(sealed)
    return sealed


def _parse_json_list(value: str, *, pattern: Any, count: int = 1) -> list[str]:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("candidate_exploit_tx_count_invalid") from exc
    if not isinstance(parsed, list) or len(parsed) != count:
        raise ValueError("candidate_exploit_tx_count_invalid")
    normalized = [str(item).lower() for item in parsed]
    if any(not pattern.fullmatch(item) for item in normalized):
        raise ValueError("candidate_exploit_tx_invalid")
    return normalized


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _actual_revision_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name in _REQUIRED_REVISION_FILES:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"cohort revision file invalid: {name}")
        hashes[name] = _sha256_file(path)
    return hashes


def _validate_revision_checksums(root: Path) -> None:
    manifest = root / "SHA256SUMS.txt"
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        digest, separator, relative_text = raw.partition("  ")
        if not separator or len(digest) != 64:
            raise ValueError("cohort checksum manifest invalid")
        relative = Path(relative_text)
        candidate = (root / relative).resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("cohort checksum path escape") from exc
        if not candidate.is_file() or candidate.is_symlink() or _sha256_file(candidate) != digest:
            raise ValueError(f"cohort checksum mismatch: {relative_text}")


def build_candidate_archive_run_plan(cohort_revision_root: str | Path) -> dict[str, Any]:
    root = Path(cohort_revision_root).expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("cohort revision root invalid")
    _validate_revision_checksums(root)
    revision_plan = json.loads((root / "revision_plan.json").read_text(encoding="utf-8"))
    if revision_plan.get("status") != "WAITING_FOR_ARCHIVE_QUALIFICATION":
        raise ValueError("cohort revision status invalid")

    candidates = {row["candidate_id"]: row for row in _read_csv(root / "screened_candidates.csv")}
    order_rows = _read_csv(root / "slot_candidate_order.csv")
    ordered_ids: list[str] = []
    seen: set[str] = set()
    for row in sorted(order_rows, key=lambda item: (item["chain"], int(item.get("global_rank") or item.get("rank") or 0), item["candidate_id"])):
        candidate_id = row["candidate_id"]
        if candidate_id not in seen:
            seen.add(candidate_id)
            ordered_ids.append(candidate_id)

    ordered: list[dict[str, Any]] = []
    prequalification_exclusions: list[dict[str, str]] = []
    for candidate_id in ordered_ids:
        row = candidates.get(candidate_id)
        if row is None:
            raise ValueError("candidate order references missing candidate")
        try:
            tx_hash = _parse_json_list(row.get("exploit_tx_hashes", ""), pattern=_TX)[0]
            addresses = _parse_json_list(row.get("target_addresses", ""), pattern=_ADDRESS)
        except ValueError as exc:
            prequalification_exclusions.append({"candidate_id": candidate_id, "code": str(exc)})
            continue
        if not str(row.get("fork_block", "")).isdigit() or int(row["fork_block"]) <= 0:
            raise ValueError("candidate incident block invalid")
        normalized = {
            "candidate_id": candidate_id,
            "case_id": candidate_id,
            "case_name": row.get("incident_name", candidate_id),
            "chain": row["chain"],
            "address": addresses[0],
            "target_contract_address": addresses[0],
            "incident_block": int(row["fork_block"]),
            "exploit_tx_hash": tx_hash,
            "incident_date": row.get("incident_date", ""),
            "source_sha256": row.get("source_sha256", ""),
            "readme_sha256": row.get("readme_sha256", ""),
        }
        normalized["input_row_sha256"] = _sha256_json(normalized)
        normalized["input_sha256"] = normalized["input_row_sha256"]
        ordered.append(normalized)

    if not ordered and prequalification_exclusions:
        raise ValueError(prequalification_exclusions[0]["code"])

    return {
        "schema_version": "candidate_archive_run_plan.v1",
        "cohort_revision_root": str(root),
        "revision_input_hashes": _actual_revision_hashes(root),
        "ordered_candidates": ordered,
        "candidate_count": len(ordered),
        "prequalification_exclusions": prequalification_exclusions,
    }


def prepare_candidate_archive_run(
    *,
    cohort_revision_root: str | Path,
    output_root: str | Path,
    revision: str,
    run_id: str,
    incident_block_policy: str = "require_fork_block_match",
) -> dict[str, Any]:
    cohort_root = Path(cohort_revision_root).expanduser().resolve()
    output = Path(output_root).expanduser().resolve(strict=False)
    run_root = output / revision / run_id
    current_hashes = _actual_revision_hashes(cohort_root)
    manifest_path = run_root / "run_manifest.json"
    if incident_block_policy not in {"require_fork_block_match", "two_provider_exploit_receipt"}:
        raise ValueError("incident block policy invalid")
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        stored_binding = str(manifest.get("binding_sha256", ""))
        binding_body = dict(manifest)
        binding_body.pop("binding_sha256", None)
        if (
            manifest.get("revision_input_hashes") != current_hashes
            or manifest.get("incident_block_policy") != incident_block_policy
            or not _SHA256.fullmatch(stored_binding)
            or _sha256_json(binding_body) != stored_binding
        ):
            raise ValueError("resume input mismatch")
        plan = build_candidate_archive_run_plan(cohort_root)
        if manifest.get("plan_sha256") != _sha256_json(plan):
            raise ValueError("resume input mismatch")
        return {"run_root": str(run_root), "plan": plan, "binding_sha256": manifest["binding_sha256"]}

    plan = build_candidate_archive_run_plan(cohort_root)
    run_root.mkdir(parents=True, exist_ok=False)
    binding = {
        "schema_version": "candidate_archive_run.v1",
        "revision": revision,
        "run_id": run_id,
        "incident_block_policy": incident_block_policy,
        "revision_input_hashes": current_hashes,
        "plan_sha256": _sha256_json(plan),
    }
    binding["binding_sha256"] = _sha256_json(binding)
    manifest_path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"run_root": str(run_root), "plan": plan, "binding_sha256": binding["binding_sha256"]}


def _hex_int(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("malformed hex quantity")
    return int(value, 16)


def _receipt_proof(
    candidate: Mapping[str, Any],
    providers: list[Any],
    *,
    receipt_root: Path,
    allow_receipt_incident_block: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    families = [str(getattr(provider, "provider_family", "unverified")) for provider in providers]
    endpoint_ids = [str(getattr(provider, "public_endpoint_id", "")) for provider in providers]
    identities = [dict(getattr(provider, "provider_identity_evidence", {}) or {}) for provider in providers]
    identity_valid = all(
        identity.get("operator_family") == family
        and identity.get("chain") == candidate.get("chain")
        and _SHA256.fullmatch(str(identity.get("endpoint_template_sha256", "")))
        for identity, family in zip(identities, families)
    )
    if (
        len(providers) < 2
        or len(set(families)) < 2
        or "unverified" in families
        or any(not endpoint_id for endpoint_id in endpoint_ids)
        or len(set(endpoint_ids)) < 2
        or not identity_valid
    ):
        return {}, ["same_family"]
    observations: list[dict[str, Any]] = []
    normalized: list[tuple[int, str, str, int, str]] = []
    for provider in providers:
        try:
            receipt_observation = provider.call("eth_getTransactionReceipt", [candidate["exploit_tx_hash"]])
            receipt = receipt_observation.result
            block_number = _hex_int(receipt["blockNumber"])
            block_hash = str(receipt["blockHash"]).lower()
            status = _hex_int(receipt["status"])
            header_observation = provider.call("eth_getBlockByNumber", [hex(block_number), False])
            header = header_observation.result
            header_number = _hex_int(header["number"])
            header_hash = str(header["hash"]).lower()
            if header_number != block_number or header_hash != block_hash:
                return {}, ["provider_disagreement"]
            paths_and_hashes = (
                (getattr(receipt_observation, "raw_response_path", ""), getattr(receipt_observation, "response_sha256", "")),
                (getattr(header_observation, "raw_response_path", ""), getattr(header_observation, "response_sha256", "")),
            )
            for raw_path_text, response_sha in paths_and_hashes:
                response_sha = str(response_sha)
                raw_path = Path(str(raw_path_text)).resolve(strict=False)
                expected = (receipt_root / response_sha[:2] / f"{response_sha}.json").resolve(strict=False)
                if (
                    not _SHA256.fullmatch(response_sha)
                    or raw_path != expected
                    or not raw_path.is_file()
                    or raw_path.is_symlink()
                    or _sha256_file(raw_path) != response_sha
                ):
                    return {}, ["receipt_path_or_hash_invalid"]
            normalized.append((block_number, block_hash, status, header_number, header_hash))
            observations.append({
                "provider_id": str(getattr(provider, "provider_id", "")),
                "provider_family": str(getattr(provider, "provider_family", "unverified")),
                "public_endpoint_id": str(getattr(provider, "public_endpoint_id", "")),
                "receipt_request_sha256": str(getattr(receipt_observation, "request_sha256", "")),
                "receipt_response_sha256": str(getattr(receipt_observation, "response_sha256", "")),
                "receipt_raw_response_path": str(getattr(receipt_observation, "raw_response_path", "")),
                "header_request_sha256": str(getattr(header_observation, "request_sha256", "")),
                "header_response_sha256": str(getattr(header_observation, "response_sha256", "")),
                "header_raw_response_path": str(getattr(header_observation, "raw_response_path", "")),
            })
        except Exception:
            return {}, ["provider_error"]
    if len(set(normalized)) != 1:
        return {}, ["provider_disagreement"]
    block_number, block_hash, status, _, _ = normalized[0]
    blockers: list[str] = []
    if status != 1:
        blockers.append("exploit_transaction_failed")
    if block_number != int(candidate["incident_block"]) and not allow_receipt_incident_block:
        blockers.append("incident_block_mismatch")
    return {
        "agreed_block_number": block_number,
        "agreed_block_hash": block_hash,
        "status": status,
        "provider_families": sorted(set(families)),
        "observations": observations,
        "proof_sha256": _sha256_json({"normalized": normalized, "observations": observations}),
    }, blockers


def _quarantine_cached(case_path: Path, candidate_id: str) -> None:
    if not case_path.exists():
        return
    try:
        cached = json.loads(case_path.read_text(encoding="utf-8"))
    except Exception:
        cached = {}
    if cached.get("status") == "VERIFIED" and cached.get("qualification_closed") is True:
        return
    quarantine = case_path.parent / "quarantine" / candidate_id
    quarantine.mkdir(parents=True, exist_ok=True)
    target = quarantine / f"retry_partial-{_sha256_file(case_path)[:16]}.json"
    os.replace(case_path, target)


def _execute_one(
    candidate: dict[str, Any],
    *,
    run_root: Path,
    binding_sha256: str,
    provider_resolver: Callable[[str, Path], list[Any]],
    case_executor: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    case_dir = run_root / "cases"
    case_dir.mkdir(parents=True, exist_ok=True)
    case_path = case_dir / f"{candidate['candidate_id']}.json"
    _quarantine_cached(case_path, candidate["candidate_id"])
    receipt_root = run_root / "receipts" / candidate["candidate_id"]
    receipt_root.mkdir(parents=True, exist_ok=True)
    try:
        providers = provider_resolver(candidate["chain"], receipt_root)
    except Exception:
        providers = []
    incident_block_policy = json.loads((run_root / "run_manifest.json").read_text(encoding="utf-8")).get(
        "incident_block_policy", "require_fork_block_match"
    )
    receipt_summary, blockers = _receipt_proof(
        candidate,
        providers,
        receipt_root=receipt_root,
        allow_receipt_incident_block=incident_block_policy == "two_provider_exploit_receipt",
    )
    historical: dict[str, Any] | None = None
    if not blockers:
        policy = {
            "require_eip1898_for_strict_snapshot": True,
            "cutoff_policy": {
                "rule": "deployment_timestamp_plus_24h",
                "primary_landmark_hours": 24,
                "minimum_incident_lead_hours": 1.0,
            },
        }
        try:
            historical_case_root = run_root / "historical_cases" / candidate["candidate_id"]
            historical_receipt_root = historical_case_root / "receipts"
            historical_providers = provider_resolver(candidate["chain"], historical_receipt_root)
            execution_candidate = dict(candidate)
            if incident_block_policy == "two_provider_exploit_receipt":
                execution_candidate["source_fork_block"] = candidate["incident_block"]
                execution_candidate["incident_block"] = receipt_summary["agreed_block_number"]
                execution_candidate["input_row_sha256"] = _sha256_json(execution_candidate)
                execution_candidate["input_sha256"] = execution_candidate["input_row_sha256"]
            historical = case_executor(
                execution_candidate,
                providers=historical_providers,
                policy=policy,
                receipt_root=historical_receipt_root,
                case_root=historical_case_root,
                resume=True,
                retry_partial=True,
            )
            if historical.get("strict_snapshot_closed") is not True:
                blockers.extend(list(historical.get("blockers") or ["strict_snapshot_partial"]))
        except Exception as exc:
            blockers.append(f"case_execution_exception:{type(exc).__name__}")
    qualified = bool(historical and historical.get("strict_snapshot_closed") is True and not blockers)
    payload = {
        "schema_version": "candidate_archive_case.v1",
        "candidate_id": candidate["candidate_id"],
        "candidate_input": candidate,
        "candidate_input_sha256": _sha256_json(candidate),
        "run_binding_sha256": binding_sha256,
        "frozen_incident_block": candidate["incident_block"],
        "incident_block_policy": incident_block_policy,
        "canonical_incident_block": receipt_summary.get("agreed_block_number") if receipt_summary else None,
        "receipt_summary": receipt_summary,
        "historical_case_sha256": _sha256_json(historical) if historical else None,
        "status": "VERIFIED" if qualified else "PARTIAL",
        "qualified": qualified,
        "qualification_closed": qualified,
        "blockers": sorted(set(blockers)),
    }
    sealed = _seal_case_envelope(payload)
    temporary = case_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(sealed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, case_path)
    return sealed


def execute_candidate_archive_qualification(
    prepared: Mapping[str, Any],
    *,
    provider_resolver: Callable[[str, Path], list[Any]],
    case_executor: Callable[..., dict[str, Any]],
    max_workers: int = 1,
) -> dict[str, Any]:
    run_root = Path(str(prepared["run_root"]))
    candidates = list(prepared["plan"]["ordered_candidates"])
    worker_count = max(1, min(int(max_workers), 4))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(
            _execute_one,
            candidate,
            run_root=run_root,
            binding_sha256=str(prepared["binding_sha256"]),
            provider_resolver=provider_resolver,
            case_executor=case_executor,
        ) for candidate in candidates]
        cases = [future.result() for future in futures]
    cases.sort(key=lambda row: (row["candidate_input"]["chain"], candidates.index(row["candidate_input"])))
    result = {
        "schema_version": "candidate_archive_qualification_result.v1",
        "run_root": str(run_root),
        "binding_sha256": prepared["binding_sha256"],
        "candidate_count": len(cases),
        "qualified_count": sum(row["qualified"] is True for row in cases),
        "cases": cases,
    }
    (run_root / "qualification_result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def default_provider_resolver(chain: str, receipt_root: Path) -> list[Any]:
    from chronosaudit_stage2.public_acquisition.managed_providers import (
        load_managed_provider_templates,
        providers_for_chain_from_managed_env,
    )

    return providers_for_chain_from_managed_env(
        chain,
        templates=load_managed_provider_templates(),
        artifact_root=receipt_root,
    )


def default_case_executor(case: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
    from chronosaudit_stage2.public_acquisition.historical_snapshot_run import execute_snapshot_case

    return execute_snapshot_case(case, **kwargs)
