from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping


SLOT_QUOTAS = {"ethereum": 16, "bsc": 38, "base": 3}
SUPPORTED_CHAINS = frozenset(SLOT_QUOTAS)
TARGET_RULE = "explicit_vulnerable_target_or_victim_contract_line"
PLAN_STATUS = "WAITING_FOR_ARCHIVE_QUALIFICATION"
OPERATIONAL_SCOPE_EXCLUSION_CODES = (
    "non_smart_contract_operational_incident",
)
_OPERATIONAL_PATTERNS = (
    r"\bphish(?:ing|ed)?\b",
    r"\bprivate[ -]?key\b",
    r"\bcredential(?:s)?\b",
    r"\bsocial[ -]?engineering\b",
    r"\brug[ -]?pull\b",
    r"\bexit[ -]?scam\b",
    r"\bmev[ -]?only\b",
    r"\bsandwich[ -]?only\b",
    r"\barbitrage[ -]?only\b",
)
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TX = re.compile(r"^0x[0-9a-fA-F]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
INPUT_CANDIDATE_FIELDS = [
    "candidate_status", "incident_date", "incident_name", "mechanism", "chain", "fork_block",
    "exploit_tx_hashes", "target_addresses", "target_extraction_rule", "source_path", "source_sha256",
    "readme_path", "readme_sha256", "public_evidence_urls", "all_source_urls", "duplicate_reasons",
    "deployment_age_status", "chain_conflict",
]
OUTPUT_CANDIDATE_FIELDS = [
    "candidate_id", *INPUT_CANDIDATE_FIELDS, "frozen_source_path", "frozen_readme_path",
]
_FORBIDDEN_COLUMN_HINTS = (
    "provider", "result", "qualification", "final", "replacement", "secret", "password", "credential",
    "api_key", "token", "endpoint",
)
PROVENANCE_OUTPUT_FIELDS = (
    "acquisition_method", "analysis_mode", "builds_or_tests_run", "commit_sha", "dependencies_installed",
    "repository_code_executed", "repository_url", "submodules_initialized", "tree_sha",
)
SCREENING_LOG_OUTPUT_FIELDS = (
    "conservative_rank_pool", "cutoff_date", "deployment_age_rule", "input_screened_rows",
    "rejection_reason_counts", "selected_top57", "selection_order", "strictly_eligible_after_deployment_age_gate",
    "target_rule", "uniqueness_rule",
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _safe_directory(path: str | Path, code: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_dir() or candidate.is_symlink():
        raise ValueError(code)
    return candidate.resolve()


def _read_json(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(code) from exc
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _read_csv(path: Path, code: str) -> tuple[list[str], list[dict[str, str]]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fields = list(reader.fieldnames or [])
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValueError(code) from exc
    if not fields:
        raise ValueError(code)
    return fields, rows


def _normalized_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _json_string_list(value: str, *, pattern: re.Pattern[str], exact_count: int | None = None) -> list[str] | None:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, list) or not parsed or not all(isinstance(item, str) and pattern.fullmatch(item) for item in parsed):
        return None
    normalized = [item.lower() for item in parsed]
    if len(normalized) != len(set(normalized)) or (exact_count is not None and len(normalized) != exact_count):
        return None
    return normalized


def _parse_checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("candidate_checksums_invalid") from exc
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or not _SHA256.fullmatch(parts[0]):
            raise ValueError("candidate_checksums_invalid")
        name = Path(parts[1]).name
        if name in result:
            raise ValueError("candidate_checksums_duplicate")
        result[name] = parts[0]
    return result


def _validate_staging_checksums(staging: Path) -> None:
    checksums = _parse_checksums(staging / "SHA256SUMS.txt")
    for name, expected in checksums.items():
        candidate = staging / name
        if not candidate.is_file() or candidate.is_symlink() or _sha256_file(candidate) != expected:
            raise ValueError(f"candidate_checksum_mismatch:{name}")
    for required in ("screened_candidates.csv", "provenance.json", "screening_log.json"):
        if required not in checksums:
            raise ValueError(f"candidate_checksum_missing:{required}")


def _validate_candidate_columns(fields: list[str]) -> None:
    extras = [field for field in fields if field not in INPUT_CANDIDATE_FIELDS]
    for field in extras:
        lowered = field.casefold()
        if any(hint in lowered for hint in _FORBIDDEN_COLUMN_HINTS):
            raise ValueError(f"candidate_forbidden_column:{field}")
    if fields != INPUT_CANDIDATE_FIELDS:
        raise ValueError("candidate_columns_mismatch")


def _constrained_metadata(source: Mapping[str, Any], fields: Iterable[str], *, schema_version: str) -> dict[str, Any]:
    return {"schema_version": schema_version, **{field: source.get(field) for field in fields}}


def _validated_repository_file(repository: Path, relative_text: str) -> Path:
    relative = Path(relative_text)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("candidate_source_path_invalid")
    lexical = repository
    for part in relative.parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise ValueError("candidate_source_path_symlink")
    resolved = lexical.resolve(strict=False)
    try:
        resolved.relative_to(repository)
    except ValueError as exc:
        raise ValueError("candidate_source_path_escape") from exc
    if not resolved.is_file():
        raise ValueError(f"candidate_source_missing:{relative_text}")
    return resolved


def _parent_contract(parent: Path, report_path: Path) -> tuple[dict[str, Any], list[dict[str, str]], list[dict[str, str]], dict[str, Any]]:
    manifest_path = parent / "run_manifest.json"
    blocker_path = parent / "blocker_ledger.csv"
    temporal_path = parent / "frozen_inputs/temporal.csv"
    manifest = _read_json(manifest_path, "parent_manifest_invalid")
    report = _read_json(report_path, "verification_report_invalid")
    if manifest.get("binding", {}).get("run_id") != "historical-snapshots-417-full-20260809":
        raise ValueError("parent_run_id_mismatch")
    if report.get("counter_authority") is not True or report.get("integrity_errors") != []:
        raise ValueError("verification_report_not_authoritative")
    if report.get("observed") != 360 or report.get("required") != 417:
        raise ValueError("verification_report_counts_mismatch")
    aggregate_hash = manifest.get("aggregate_hashes", {}).get("blocker_ledger")
    if aggregate_hash != _sha256_file(blocker_path):
        raise ValueError("parent_blocker_hash_mismatch")
    _, blockers = _read_csv(blocker_path, "parent_blocker_ledger_invalid")
    _, population = _read_csv(temporal_path, "parent_population_invalid")
    blocker_set = {(row.get("chain"), row.get("case_id"), row.get("code")) for row in blockers}
    report_set = {
        (row.get("chain"), row.get("case_id"), row.get("code"))
        for row in report.get("scientific_blockers", [])
        if isinstance(row, dict)
    }
    if len(blockers) != 57 or blocker_set != report_set:
        raise ValueError("parent_blocker_set_mismatch")
    if any(row.get("code") != "insufficient_incident_lead_time" for row in blockers):
        raise ValueError("parent_blocker_code_mismatch")
    if Counter(row.get("chain") for row in blockers) != Counter(SLOT_QUOTAS):
        raise ValueError("parent_blocker_quota_mismatch")
    if len(population) != 417:
        raise ValueError("parent_population_count_mismatch")
    report_hashes = report.get("authoritative_input_hashes", {})
    if report_hashes.get("aggregate_hashes") != manifest.get("aggregate_hashes"):
        raise ValueError("verification_parent_hash_binding_mismatch")
    return manifest, blockers, population, report


def _candidate_id(row: Mapping[str, str], address: str, transactions: list[str]) -> str:
    identity = {
        "chain": row["chain"],
        "incident_date": row["incident_date"],
        "incident_name": _normalized_name(row["incident_name"]),
        "target_address": address,
        "primary_tx": transactions[0],
        "source_path": row["source_path"],
        "source_sha256": row["source_sha256"],
    }
    return "ca2r-" + _sha256_bytes(_canonical_json(identity))[:20]


def _operational_exclusion(row: Mapping[str, str]) -> str | None:
    text = f"{row.get('incident_name', '')} {row.get('mechanism', '')}".casefold()
    if any(re.search(pattern, text) for pattern in _OPERATIONAL_PATTERNS):
        return "non_smart_contract_operational_incident"
    return None


def _screen_candidates(
    rows: Iterable[dict[str, str]], *, repository: Path, population: list[dict[str, str]]
) -> tuple[list[dict[str, str]], Counter[str]]:
    parent_addresses = {(row["chain"], row["target_contract_address"].lower()) for row in population}
    parent_names = {(row["chain"], _normalized_name(row["incident_name"]), row["incident_date"]) for row in population}
    parent_txs = {
        (row["chain"], tx.lower())
        for row in population
        for tx in (json.loads(row.get("incident_tx_hashes") or "[]"))
    }
    exclusions: Counter[str] = Counter()
    parsed: list[dict[str, str]] = []
    for source_row in rows:
        row = {key: str(value or "") for key, value in source_row.items()}
        if not _SHA256.fullmatch(row["source_sha256"]) or not _SHA256.fullmatch(row["readme_sha256"]):
            raise ValueError("candidate_source_hash_invalid")
        for path_field, hash_field in (("source_path", "source_sha256"), ("readme_path", "readme_sha256")):
            resolved = _validated_repository_file(repository, row[path_field])
            if _sha256_file(resolved) != row[hash_field]:
                raise ValueError(f"candidate_source_hash_mismatch:{row[path_field]}")
            row[f"_{path_field}_validated_path"] = str(resolved)
        reason = _operational_exclusion(row)
        if reason:
            exclusions[reason] += 1
            continue
        addresses = _json_string_list(row["target_addresses"], pattern=_ADDRESS, exact_count=1)
        transactions = _json_string_list(row["exploit_tx_hashes"], pattern=_TX)
        checks = (
            (row["candidate_status"] == "screened_candidate_needs_deployment_age_verification", "candidate_status_invalid"),
            (row["target_extraction_rule"] == TARGET_RULE, "target_rule_invalid"),
            (not row["duplicate_reasons"].strip(), "duplicate_reason_present"),
            (row["chain_conflict"].casefold() == "false", "chain_conflict"),
            (row["chain"] in SUPPORTED_CHAINS, "unsupported_chain"),
            (addresses is not None, "target_address_invalid"),
            (transactions is not None, "exploit_tx_invalid"),
            (row["fork_block"].isdigit() and int(row["fork_block"]) > 0, "fork_block_invalid"),
        )
        failed = next((code for passed, code in checks if not passed), None)
        if failed:
            exclusions[failed] += 1
            continue
        assert addresses is not None and transactions is not None
        address = addresses[0]
        collision = (
            (row["chain"], address) in parent_addresses
            or (row["chain"], _normalized_name(row["incident_name"]), row["incident_date"]) in parent_names
            or any((row["chain"], tx) in parent_txs for tx in transactions)
        )
        if collision:
            exclusions["parent_population_collision"] += 1
            continue
        row["candidate_id"] = _candidate_id(row, address, transactions)
        row["_address"] = address
        row["_transactions"] = json.dumps(transactions, separators=(",", ":"))
        parsed.append(row)

    accepted: list[dict[str, str]] = []
    seen_addresses: set[tuple[str, str]] = set()
    seen_names: set[tuple[str, str, str]] = set()
    seen_txs: set[tuple[str, str]] = set()
    for row in sorted(parsed, key=lambda item: item["candidate_id"]):
        txs = json.loads(row["_transactions"])
        keys = (
            (row["chain"], row["_address"]),
            (row["chain"], _normalized_name(row["incident_name"]), row["incident_date"]),
        )
        if keys[0] in seen_addresses or keys[1] in seen_names or any((row["chain"], tx) in seen_txs for tx in txs):
            exclusions["candidate_collision"] += 1
            continue
        seen_addresses.add(keys[0])
        seen_names.add(keys[1])
        seen_txs.update((row["chain"], tx) for tx in txs)
        accepted.append(row)
    return accepted, exclusions


def _write_csv(path: Path, fields: list[str], rows: Iterable[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_cohort_revision(
    *,
    parent_run_root: str | Path,
    verification_report_path: str | Path,
    candidate_staging_root: str | Path,
    candidate_repository_root: str | Path,
    output_root: str | Path,
    seed: str,
) -> dict[str, Any]:
    parent = _safe_directory(parent_run_root, "parent_run_root_invalid")
    staging = _safe_directory(candidate_staging_root, "candidate_staging_root_invalid")
    repository = _safe_directory(candidate_repository_root, "candidate_repository_root_invalid")
    report_path = Path(verification_report_path).expanduser().resolve()
    output = Path(output_root).expanduser().resolve(strict=False)
    if not seed:
        raise ValueError("seed_blank")
    if output.exists() or output.parent.is_symlink():
        raise ValueError("output_root_exists_or_invalid")

    manifest, blockers, population, report = _parent_contract(parent, report_path)
    _validate_staging_checksums(staging)
    provenance = _read_json(staging / "provenance.json", "candidate_provenance_invalid")
    screening_log = _read_json(staging / "screening_log.json", "candidate_screening_log_invalid")
    fields, source_rows = _read_csv(staging / "screened_candidates.csv", "candidate_rows_invalid")
    _validate_candidate_columns(fields)
    candidates, exclusions = _screen_candidates(source_rows, repository=repository, population=population)
    by_chain = {chain: [row for row in candidates if row["chain"] == chain] for chain in SUPPORTED_CHAINS}
    for chain, quota in SLOT_QUOTAS.items():
        if len(by_chain[chain]) < quota:
            raise ValueError(f"candidate_quota_insufficient:{chain}")

    slots = sorted(blockers, key=lambda row: (row["chain"], row["case_id"]))
    chain_orders: dict[str, list[tuple[str, dict[str, str]]]] = {}
    for chain, chain_candidates in by_chain.items():
        scored: list[tuple[str, dict[str, str]]] = []
        for candidate in chain_candidates:
            primary_tx = json.loads(candidate["_transactions"])[0]
            value = "|".join((seed, chain, candidate["candidate_id"], candidate["source_sha256"], primary_tx))
            scored.append((_sha256_bytes(value.encode("utf-8")), candidate))
        scored.sort(key=lambda item: (item[0], item[1]["candidate_id"]))
        chain_orders[chain] = scored

    slots_by_chain = {
        chain: [slot for slot in slots if slot["chain"] == chain]
        for chain in SUPPORTED_CHAINS
    }
    primary_by_slot: dict[str, str] = {}
    for chain, chain_slots in slots_by_chain.items():
        for slot, (_, candidate) in zip(chain_slots, chain_orders[chain]):
            primary_by_slot[slot["case_id"]] = candidate["candidate_id"]

    order_rows: list[dict[str, Any]] = []
    for slot in slots:
        primary_id = primary_by_slot[slot["case_id"]]
        for global_rank, (rank_hash, candidate) in enumerate(chain_orders[slot["chain"]], 1):
            order_rows.append({
                "slot_case_id": slot["case_id"], "chain": slot["chain"], "global_rank": global_rank,
                "candidate_id": candidate["candidate_id"], "rank_sha256": rank_hash,
                "assignment_role": "PRIMARY" if candidate["candidate_id"] == primary_id else "ALTERNATE",
            })

    parent_paths = {
        "run_manifest": parent / "run_manifest.json",
        "blocker_ledger": parent / "blocker_ledger.csv",
        "temporal_population": parent / "frozen_inputs/temporal.csv",
        "verification_report": report_path,
    }
    plan: dict[str, Any] = {
        "schema_version": "historical_snapshot_cohort_revision_plan.v1",
        "status": PLAN_STATUS,
        "no_provider_results_observed": True,
        "seed": seed,
        "parent_run_id": manifest["binding"]["run_id"],
        "parent_artifacts": {
            name: {"path": str(path), "sha256": _sha256_file(path)} for name, path in parent_paths.items()
        },
        "parent_authoritative_input_hashes": report["authoritative_input_hashes"],
        "slot_count": len(slots),
        "slot_quotas": SLOT_QUOTAS,
        "eligible_candidate_counts": {chain: len(rows) for chain, rows in sorted(by_chain.items())},
        "candidate_exclusion_counts": dict(sorted(exclusions.items())),
        "operational_scope_exclusion_codes": list(OPERATIONAL_SCOPE_EXCLUSION_CODES),
        "candidate_source": {
            "repository_url": provenance.get("repository_url"),
            "commit_sha": provenance.get("commit_sha"),
            "tree_sha": provenance.get("tree_sha"),
            "screening_cutoff_date": screening_log.get("cutoff_date"),
        },
        "selection_contract": {
            "primary_unique_across_slots": True,
            "alternates_may_repeat_across_slots": True,
            "finalization_requires_one_to_one": True,
            "chain_global_order_frozen": True,
            "slot_independent_ranking": True,
            "maximizes_same_chain_fill_before_archive_results": True,
            "rank_formula": "SHA256(seed|chain|candidate id|source sha|primary tx)",
            "assignment_method": "sorted slots receive distinct candidates in chain-global rank order; all slots retain the unchanged full chain-global order",
        },
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        frozen_rows = []
        for row in sorted(candidates, key=lambda item: item["candidate_id"]):
            source_relative = Path(row["source_path"])
            readme_relative = Path(row["readme_path"])
            frozen_source = Path("candidate_sources") / row["candidate_id"] / "source" / source_relative
            frozen_readme = Path("candidate_sources") / row["candidate_id"] / "readme" / readme_relative
            for frozen_path, source_path in (
                (frozen_source, Path(row["_source_path_validated_path"])),
                (frozen_readme, Path(row["_readme_path_validated_path"])),
            ):
                target = temporary / frozen_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_path, target)
            frozen_rows.append({
                **{key: row.get(key, "") for key in ["candidate_id", *INPUT_CANDIDATE_FIELDS]},
                "frozen_source_path": frozen_source.as_posix(),
                "frozen_readme_path": frozen_readme.as_posix(),
            })
        _write_csv(temporary / "screened_candidates.csv", OUTPUT_CANDIDATE_FIELDS, frozen_rows)
        constrained_provenance = _constrained_metadata(
            provenance, PROVENANCE_OUTPUT_FIELDS, schema_version="cohort_revision_candidate_provenance.v1"
        )
        constrained_screening_log = _constrained_metadata(
            screening_log, SCREENING_LOG_OUTPUT_FIELDS, schema_version="cohort_revision_screening_log.v1"
        )
        (temporary / "provenance.json").write_text(
            json.dumps(constrained_provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (temporary / "screening_log.json").write_text(
            json.dumps(constrained_screening_log, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        staging_output = temporary / "staging"
        staging_output.mkdir()
        shutil.copyfile(staging / "screened_candidates.csv", staging_output / "screened_candidates.csv")
        (staging_output / "provenance.json").write_text(
            json.dumps(constrained_provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (staging_output / "screening_log.json").write_text(
            json.dumps(constrained_screening_log, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        staged_names = ("screened_candidates.csv", "provenance.json", "screening_log.json")
        staged_checksums = "".join(
            f"{_sha256_file(staging_output / name)}  {name}\n" for name in staged_names
        )
        (staging_output / "SHA256SUMS.txt").write_text(staged_checksums, encoding="utf-8")
        root_staged_checksums = "".join(
            f"{_sha256_file(staging_output / name)}  staging/{name}\n" for name in staged_names
        )
        (temporary / "source_SHA256SUMS.txt").write_text(root_staged_checksums, encoding="utf-8")
        _write_csv(temporary / "replacement_slots.csv", ["chain", "slot_case_id", "blocker_code"], (
            {"chain": row["chain"], "slot_case_id": row["case_id"], "blocker_code": row["code"]} for row in slots
        ))
        _write_csv(
            temporary / "slot_candidate_order.csv",
            ["slot_case_id", "chain", "global_rank", "candidate_id", "rank_sha256", "assignment_role"],
            order_rows,
        )
        (temporary / "revision_plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        artifact_paths = sorted(
            path for path in temporary.rglob("*") if path.is_file() and path != temporary / "SHA256SUMS.txt"
        )
        checksum_text = "".join(
            f"{_sha256_file(path)}  {path.relative_to(temporary).as_posix()}\n" for path in artifact_paths
        )
        (temporary / "SHA256SUMS.txt").write_text(checksum_text, encoding="utf-8")
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return plan
