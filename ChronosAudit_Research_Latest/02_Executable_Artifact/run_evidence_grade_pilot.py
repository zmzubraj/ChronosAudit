#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import urlparse

import pandas as pd
import yaml
from jsonschema import Draft202012Validator

from chronosaudit_stage2.onchain import (
    JsonRpcProvider,
    canonical_block_selector,
    historical_identity_snapshot,
    normalize_hex,
    provider_consensus,
)
from chronosaudit_stage2.public_acquisition.pilot import (
    apply_prespecified_pilot_replacement,
    build_postfreeze_pilot_amendment,
    first_block_at_or_after_timestamp,
    snapshot_state_cells,
    verify_cutoff_block_bracket,
    verify_snapshot_receipt_bindings,
)
from chronosaudit_stage2.public_acquisition.strict_snapshot import (
    RPC_RECEIPT_MANIFEST_SCHEMA_VERSION,
    STRICT_SNAPSHOT_SCHEMA_VERSION,
    validate_strict_historical_snapshot,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "config" / "evidence_grade_pilot_amendment_a2.yaml"
DEFAULT_RUN_ROOT = ROOT / "reports" / "public_acquisition" / "2026-08-09" / "evidence-grade-pilot-amendment-a2"
DEFAULT_RAW_ROOT = ROOT / "raw" / "public_acquisition" / "2026-08-09" / "evidence-grade-pilot-amendment-a2"
DEFAULT_PROCESSED_ROOT = ROOT / "processed" / "public_acquisition" / "2026-08-09" / "evidence-grade-pilot-amendment-a2"
REQUIRED_STATE_CELLS = (
    "block_capability",
    "runtime_code",
    "eip1967_implementation_slot",
    "eip1967_beacon_slot",
    "eip1967_admin_slot",
    "beacon_implementation_call",
    "implementation_runtime_code",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_file_if_present(path: Path) -> str | None:
    return _sha256_file(path) if path.is_file() else None


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def _deep_merge(parent: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    merged = dict(parent)
    for key, value in child.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_config(config_path: Path) -> dict[str, Any]:
    child = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    parent_value = child.get("parent_config")
    if not parent_value:
        return child
    parent_path = (ROOT / str(parent_value)).resolve()
    try:
        parent_path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError("parent config escapes executable root") from exc
    if _sha256_file(parent_path) != str(child.get("parent_config_sha256", "")).lower():
        raise ValueError("parent config hash mismatch")
    return _deep_merge(yaml.safe_load(parent_path.read_text(encoding="utf-8")), child)


def _write_receipt_manifest(receipt_root: Path, run_root: Path) -> dict[str, Any]:
    """Inventory every preserved response and verify its content-addressed name."""
    entries: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted(receipt_root.rglob("*.json")):
        if path.is_symlink() or not path.is_file():
            invalid.append(path.as_posix())
            continue
        digest = _sha256_file(path)
        name_matches_digest = path.stem.lower() == digest
        if not name_matches_digest:
            invalid.append(path.as_posix())
        entries.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": digest,
                "bytes": path.stat().st_size,
                "content_address_valid": name_matches_digest,
            }
        )
    manifest = {
        "schema_version": RPC_RECEIPT_MANIFEST_SCHEMA_VERSION,
        "receipt_count": len(entries),
        "total_bytes": sum(item["bytes"] for item in entries),
        "all_content_addresses_valid": not invalid,
        "invalid_paths": invalid,
        "entries": entries,
        "created_at_utc": _utc_now(),
    }
    manifest["manifest_sha256_without_self_hash"] = _sha256_json(manifest)
    schema = json.loads((ROOT / "schemas" / "rpc_receipt_manifest.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(manifest)
    _atomic_json(run_root / "rpc_receipt_manifest.json", manifest)
    return manifest


def _portable(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _portable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_portable(item) for item in value]
    if isinstance(value, str) and Path(value).is_absolute():
        try:
            return Path(value).resolve().relative_to(ROOT.resolve()).as_posix()
        except ValueError:
            return value
    return value


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _clean_value(value: Any) -> Any:
    if pd.isna(value):
        return None
    if isinstance(value, dict):
        return {key: _clean_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clean_value(item) for item in value]
    return value


def _provider_identity_contract(
    identity_verification: dict[str, Any],
    providers: list[JsonRpcProvider],
) -> dict[str, Any]:
    verified_by_family = {
        str(item.get("family_id", "")).strip().lower(): dict(item)
        for item in list(identity_verification.get("families", []) or [])
        if str(item.get("family_id", "")).strip()
    }
    families = []
    for family_id, verification in verified_by_family.items():
        family_providers = [provider for provider in providers if str(provider.provider_family).strip().lower() == family_id]
        if not family_providers:
            continue
        checks = list(verification.get("evidence", []) or [])
        first_check = dict(checks[0]) if checks else {}
        families.append(
            {
                "family_id": family_id,
                "operator_verified": bool(verification.get("operator_verified")),
                "complete": bool(verification.get("complete")) and bool(family_providers),
                "endpoint_template_sha256": family_providers[0].public_endpoint_id,
                "evidence": [
                    {
                        "provider_id": provider.provider_id,
                        "provider_identity": provider.public_endpoint_id,
                        "captured_path": first_check.get("captured_path"),
                        "sha256": first_check.get("sha256"),
                        "actual_sha256": first_check.get("actual_sha256"),
                        "valid": first_check.get("valid"),
                        "endpoint_template_sha256": provider.public_endpoint_id,
                    }
                    for provider in family_providers
                ],
            }
        )
    return {"complete": len({item["family_id"] for item in families if item["complete"]}) >= 2, "families": families}


def _artifact_hash_payload(snapshot: dict[str, Any]) -> dict[str, Any]:
    payload = dict(snapshot)
    # Validation metadata is runtime-only and excluded so the artifact can be
    # sealed after all blocker/closure mutations without recursive instability.
    payload.pop("strict_snapshot_validation", None)
    payload.pop("artifact_sha256_without_self_hash", None)
    payload.pop("artifact_sha256", None)
    return payload


def _attach_strict_contract_metadata(
    result: dict[str, Any],
    *,
    row: dict[str, Any],
    config: dict[str, Any],
    providers: list[JsonRpcProvider],
    provider_identity: dict[str, Any],
    receipt_root: Path,
) -> dict[str, Any]:
    case_input = _clean_value(row)
    policy_input = {
        "cutoff_policy": _clean_value(config["cutoff_policy"]),
        "provider_identity": provider_identity,
    }
    enriched = dict(result)
    enriched["schema_version"] = STRICT_SNAPSHOT_SCHEMA_VERSION
    enriched["case_input"] = case_input
    enriched["case_input_sha256"] = _sha256_json(case_input)
    enriched["policy_input"] = policy_input
    enriched["policy_sha256"] = _sha256_json(policy_input)
    enriched["provider_identity"] = provider_identity
    enriched["provider_identity_sha256"] = _sha256_json(provider_identity)
    schema = json.loads((ROOT / "schemas" / "strict_historical_snapshot.schema.json").read_text(encoding="utf-8"))
    provisional = _artifact_hash_payload(enriched)
    provisional["artifact_sha256_without_self_hash"] = _sha256_json(provisional)
    provisional["artifact_sha256"] = _sha256_json(
        {
            **provisional,
            "artifact_sha256_without_self_hash": provisional["artifact_sha256_without_self_hash"],
        }
    )
    validation = validate_strict_historical_snapshot(
        provisional,
        schema=schema,
        receipt_root=receipt_root,
        provider_identity=provider_identity,
    )
    enriched = dict(provisional)
    if not validation.ok:
        enriched["strict_snapshot_closed"] = False
        enriched["blockers"] = sorted(set(list(enriched.get("blockers", [])) + list(validation.errors)))
    if not enriched.get("strict_snapshot_closed") and not enriched.get("blocked_reason"):
        enriched["blocked_reason"] = enriched["blockers"][0] if enriched.get("blockers") else "strict_snapshot_not_closed"
    sealed = _artifact_hash_payload(enriched)
    sealed["artifact_sha256_without_self_hash"] = _sha256_json(sealed)
    sealed["artifact_sha256"] = _sha256_json(
        {
            **sealed,
            "artifact_sha256_without_self_hash": sealed["artifact_sha256_without_self_hash"],
        }
    )
    # Validation metadata is attached after sealing and remains outside the hash domain.
    sealed_validation = validate_strict_historical_snapshot(
        sealed,
        schema=schema,
        receipt_root=receipt_root,
        provider_identity=provider_identity,
    )
    sealed["strict_snapshot_validation"] = sealed_validation.to_dict()
    return sealed


def _normal_header(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("malformed block header")
    return {
        "number": int(str(value["number"]), 16),
        "hash": normalize_hex(value["hash"]),
        "timestamp": int(str(value["timestamp"]), 16),
    }


def _providers(config: dict[str, Any], chain: str, receipt_root: Path) -> list[JsonRpcProvider]:
    endpoints = config["providers"][chain]
    primary_id = f"sentio-{chain}"
    primary_family = "sentio"
    primary_url = endpoints["sentio"]
    secondary_id = f"blast-{chain}"
    secondary_family = "alchemy-blast"
    secondary_url = endpoints["alchemy-blast"]
    if chain == "arbitrum" and (infura_url := os.environ.get("CHRONOS_INFURA_ARBITRUM_URL")):
        parsed = urlparse(infura_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "arbitrum-mainnet.infura.io"
            or not parsed.path.startswith("/v3/")
            or len(parsed.path.removeprefix("/v3/")) < 1
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("invalid CHRONOS_INFURA_ARBITRUM_URL")
        primary_id = "infura-arbitrum"
        primary_family = "infura"
        primary_url = infura_url
    if chain == "arbitrum" and (alchemy_url := os.environ.get("CHRONOS_ALCHEMY_ARBITRUM_URL")):
        parsed = urlparse(alchemy_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "arb-mainnet.g.alchemy.com"
            or not parsed.path.startswith("/v2/")
            or len(parsed.path.removeprefix("/v2/")) < 1
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("invalid CHRONOS_ALCHEMY_ARBITRUM_URL")
        secondary_id = "alchemy-arbitrum"
        secondary_family = "alchemy"
        secondary_url = alchemy_url
    return [
        JsonRpcProvider(
            primary_id,
            primary_url,
            timeout=20,
            max_retries=1,
            backoff_seconds=0.25,
            provider_family=primary_family,
            artifact_root=receipt_root,
        ),
        JsonRpcProvider(
            secondary_id,
            secondary_url,
            timeout=20,
            max_retries=1,
            backoff_seconds=0.25,
            provider_family=secondary_family,
            artifact_root=receipt_root,
        ),
    ]


def _verify_provider_identity(config: dict[str, Any]) -> dict[str, Any]:
    families: list[dict[str, Any]] = []
    complete = True
    for family in config["provider_families"]:
        checks = []
        for evidence in family["operator_evidence"]:
            path = ROOT / evidence["captured_path"]
            actual = _sha256_file(path) if path.is_file() and not path.is_symlink() else None
            valid = actual == evidence["sha256"]
            complete = complete and valid
            checks.append({**evidence, "actual_sha256": actual, "valid": valid})
        families.append(
            {
                "family_id": family["family_id"],
                "operator_verified": bool(family["operator_verified"]),
                "evidence": checks,
                "complete": bool(family["operator_verified"] and all(item["valid"] for item in checks)),
            }
        )
    if len({family["family_id"] for family in families if family["complete"]}) < 2:
        complete = False
    return {"complete": complete, "families": families, "checked_at_utc": _utc_now()}


def _verify_code_transition(
    providers: list[JsonRpcProvider],
    *,
    address: str,
    deployment_block: int,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    code: dict[str, Any] = {}
    for label, block_number in (("previous", deployment_block - 1), ("deployment", deployment_block)):
        header = provider_consensus(
            providers,
            "eth_getBlockByNumber",
            [hex(block_number), False],
            _normal_header,
            require_distinct_provider_families=True,
        )
        headers[label] = header
        if header.get("status") != "consensus":
            code[label] = {"status": "blocked_no_canonical_block_consensus", "value": None, "observations": []}
            continue
        code[label] = provider_consensus(
            providers,
            "eth_getCode",
            [address, canonical_block_selector(header["value"]["hash"])],
            normalize_hex,
            require_distinct_provider_families=True,
        )
    blockers: list[str] = []
    if code["previous"].get("status") != "consensus" or code["previous"].get("value") != "0x":
        blockers.append("code_not_absent_immediately_before_deployment")
    if code["deployment"].get("status") != "consensus" or code["deployment"].get("value") in (None, "0x"):
        blockers.append("code_not_present_at_deployment")
    return {"status": "VERIFIED" if not blockers else "PARTIAL", "blockers": blockers, "headers": headers, "code": code}


def _load_amended_pilot(config: dict[str, Any]) -> tuple[pd.DataFrame, dict[str, Any]]:
    base_path = ROOT / config["base_pilot_csv"]
    if _sha256_file(base_path) != config["base_pilot_sha256"]:
        raise ValueError("frozen base pilot hash mismatch")
    base = pd.read_csv(base_path)
    supplement = config["supplement"]
    candidate = pd.DataFrame(
        [
            {
                **supplement,
                "target_contract_address": supplement["address"],
                "fork_block_number": supplement["incident_block"],
                "prediction_cutoff_block": supplement["deployment_block"] + 1,
                "candidate_source_sha256": supplement["poc_sha256"],
                "eligibility_status": "VERIFIED",
                "pilot_member": True,
            }
        ]
    )
    amended, parent_audit = build_postfreeze_pilot_amendment(
        base,
        candidate,
        seed=config["selection"]["seed"],
        base_manifest_sha256=config["base_pilot_sha256"],
        amendment_id=config.get("parent_amendment_id", config["amendment_id"]),
    )
    audit = parent_audit
    if replacement := config.get("replacement"):
        expected_parent_manifest = str(config["parent_pilot_manifest_sha256"]).lower()
        if parent_audit["amended_manifest_sha256"] != expected_parent_manifest:
            raise ValueError("parent pilot manifest hash mismatch")
        for screened in config["selection"].get("screened_before_freeze", []):
            screened_path = ROOT / screened["candidate_source_path"]
            if _sha256_file(screened_path) != screened["candidate_source_sha256"]:
                raise ValueError("screened candidate source hash mismatch")
        poc_path = ROOT / replacement["poc_path"]
        if _sha256_file(poc_path) != replacement["poc_sha256"]:
            raise ValueError("replacement PoC hash mismatch")
        for evidence in replacement.get("incident_evidence", {}).values():
            evidence_path = ROOT / evidence["path"]
            if _sha256_file(evidence_path) != evidence["sha256"]:
                raise ValueError("replacement incident evidence hash mismatch")
        replacement_row = {
            **replacement,
            "target_contract_address": replacement["address"],
            "fork_block_number": replacement["poc_fork_block"],
            "prediction_cutoff_block": int(replacement["deployment_block"]) + 1,
            "candidate_source_sha256": replacement["poc_sha256"],
            "eligibility_status": "VERIFIED",
            "pilot_member": True,
        }
        amended, audit = apply_prespecified_pilot_replacement(
            amended,
            replacement_row,
            failed_case_name=replacement["failed_case_name"],
            failure_reason=replacement["failure_reason"],
            seed=config["selection"]["replacement_seed"],
            amendment_id=config["amendment_id"],
            parent_manifest_sha256=expected_parent_manifest,
        )
        audit["parent_amendment_id"] = config["parent_amendment_id"]
        audit["parent_audit"] = parent_audit
    for index, row in amended.iterrows():
        case_name = str(row["case_name"]).lower()
        deployment = config["deployment_evidence"][case_name]
        amended.at[index, "deployment_block"] = int(deployment["deployment_block"])
        amended.at[index, "creation_tx_hash"] = deployment.get("creation_tx_hash")
        amended.at[index, "creation_evidence_type"] = deployment["creation_evidence_type"]
    amended["deployment_block"] = pd.to_numeric(amended["deployment_block"], errors="raise").astype("Int64")
    return amended, audit


def _run_case(
    row: dict[str, Any],
    *,
    config: dict[str, Any],
    provider_identity_verification: dict[str, Any],
    receipt_root: Path,
    cached_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    case_name = str(row["case_name"]).lower()
    chain = str(row["chain"]).lower()
    address = str(row.get("address") or row["target_contract_address"]).lower()
    incident_block = int(row["incident_block"])
    raw_deployment_block = row.get("deployment_block")
    try:
        deployment_block = int(raw_deployment_block)
    except (TypeError, ValueError):
        return _attach_strict_contract_metadata(
            {
                "case_id": row["case_id"],
                "case_name": case_name,
                "chain": chain,
                "address": address,
                "program_case": bool(row.get("program_case", True)),
                "deployment_block": raw_deployment_block,
                "deployment_timestamp": None,
                "creation_tx_hash": None if pd.isna(row.get("creation_tx_hash")) else row.get("creation_tx_hash"),
                "creation_evidence_type": row.get("creation_evidence_type"),
                "prediction_cutoff_policy": config["cutoff_policy"]["rule"],
                "prediction_cutoff_target_timestamp": None,
                "prediction_cutoff_block": row.get("prediction_cutoff_block"),
                "prediction_cutoff_timestamp": None,
                "prediction_cutoff_block_hash": None,
                "incident_block": incident_block,
                "incident_timestamp": None,
                "cutoff_lead_hours": None,
                "provider_families": [],
                "deployment_transition": {"status": "PARTIAL", "blockers": ["missing_deployment_block"], "headers": {}, "code": {}},
                "cutoff_search": {},
                "cutoff_bracket": {"status": "PARTIAL", "blockers": ["missing_deployment_block"]},
                "incident_block_consensus": {"status": "PARTIAL", "value": None, "observations": []},
                "snapshot": {"status": "partial_or_disputed"},
                "state_cells": {},
                "receipt_bindings": {"complete": False, "cells": {}},
                "required_state_cells": list(REQUIRED_STATE_CELLS),
                "strict_snapshot_closed": False,
                "blocked_reason": "missing_deployment_block",
                "blockers": ["missing_deployment_block"],
                "completed_at_utc": _utc_now(),
            },
            row=row,
            config=config,
            providers=[],
            provider_identity=provider_identity_verification,
            receipt_root=receipt_root,
        )
    providers = _providers(config, chain, receipt_root)
    provider_identity = _provider_identity_contract(provider_identity_verification, providers)
    transition = _verify_code_transition(providers, address=address, deployment_block=deployment_block)
    deployment_header = transition["headers"]["deployment"]
    if deployment_header.get("status") != "consensus":
        blockers = sorted(set(list(transition.get("blockers", [])) + ["deployment_header_no_independent_consensus"]))
        return _attach_strict_contract_metadata(
            {
                "case_id": row["case_id"],
                "case_name": case_name,
                "chain": chain,
                "address": address,
                "program_case": bool(row.get("program_case", True)),
                "deployment_block": deployment_block,
                "deployment_timestamp": None,
                "creation_tx_hash": None if pd.isna(row.get("creation_tx_hash")) else row.get("creation_tx_hash"),
                "creation_evidence_type": row.get("creation_evidence_type"),
                "prediction_cutoff_policy": config["cutoff_policy"]["rule"],
                "prediction_cutoff_target_timestamp": None,
                "prediction_cutoff_block": row.get("prediction_cutoff_block"),
                "prediction_cutoff_timestamp": None,
                "prediction_cutoff_block_hash": None,
                "incident_block": incident_block,
                "incident_timestamp": None,
                "cutoff_lead_hours": None,
                "provider_families": sorted({provider.provider_family for provider in providers}),
                "deployment_transition": transition,
                "cutoff_search": {},
                "cutoff_bracket": {"status": "PARTIAL", "blockers": blockers},
                "incident_block_consensus": {"status": "PARTIAL", "value": None, "observations": []},
                "snapshot": {"status": "partial_or_disputed"},
                "state_cells": {},
                "receipt_bindings": {"complete": False, "cells": {}},
                "required_state_cells": list(REQUIRED_STATE_CELLS),
                "strict_snapshot_closed": False,
                "blocked_reason": blockers[0],
                "blockers": blockers,
                "completed_at_utc": _utc_now(),
            },
            row=row,
            config=config,
            providers=providers,
            provider_identity=provider_identity,
            receipt_root=receipt_root,
        )
    deployment_timestamp = int(deployment_header["value"]["timestamp"])
    target_timestamp = deployment_timestamp + int(config["cutoff_policy"]["primary_landmark_hours"]) * 3600

    frozen_landmark = config.get("cutoff_landmarks", {}).get(case_name)
    cached_search = (cached_result or {}).get("cutoff_search", {})
    if frozen_landmark and int(frozen_landmark.get("target_timestamp", -1)) == target_timestamp:
        search = {
            "target_timestamp": target_timestamp,
            "previous_block": frozen_landmark["previous_block"],
            "cutoff_block": frozen_landmark["cutoff_block"],
            "binary_search_observations": [],
            "reused_from_verified_landmark_config": True,
        }
    elif (
        cached_result
        and cached_result.get("address") == address
        and int(cached_result.get("deployment_block", -1)) == deployment_block
        and int(cached_search.get("target_timestamp", -1)) == target_timestamp
        and cached_search.get("previous_block", {}).get("number") is not None
        and cached_search.get("cutoff_block", {}).get("number") is not None
    ):
        search = {
            "target_timestamp": target_timestamp,
            "previous_block": cached_search["previous_block"],
            "cutoff_block": cached_search["cutoff_block"],
            "binary_search_observations": cached_search.get("binary_search_observations", []),
            "reused_from_prior_case_artifact": True,
        }
    else:
        search = first_block_at_or_after_timestamp(
            providers[1],
            target_timestamp=target_timestamp,
            lower_block=deployment_block,
            upper_block=incident_block,
        )
    cutoff_number = int(search["cutoff_block"]["number"])
    previous_number = int(search["previous_block"]["number"])
    bracket = verify_cutoff_block_bracket(
        providers,
        target_timestamp=target_timestamp,
        previous_block_number=previous_number,
        cutoff_block_number=cutoff_number,
    )
    incident = provider_consensus(
        providers,
        "eth_getBlockByNumber",
        [hex(incident_block), False],
        _normal_header,
        require_distinct_provider_families=True,
    )
    incident_timestamp = int(incident["value"]["timestamp"]) if incident.get("status") == "consensus" else None
    lead_hours = (incident_timestamp - int(bracket["cutoff"]["value"]["timestamp"])) / 3600 if incident_timestamp else None

    snapshot = historical_identity_snapshot(address, cutoff_number, providers, strict_provider_families=True)
    cells = snapshot_state_cells(snapshot, providers=providers)
    bindings = verify_snapshot_receipt_bindings(cells, required_cells=REQUIRED_STATE_CELLS, allowed_root=receipt_root)
    blockers: list[str] = []
    if transition["status"] != "VERIFIED":
        blockers.extend(transition["blockers"])
    if bracket["status"] != "VERIFIED":
        blockers.extend(bracket["blockers"])
    if incident.get("status") != "consensus":
        blockers.append("incident_block_no_independent_consensus")
    if lead_hours is None or lead_hours < float(config["cutoff_policy"]["minimum_incident_lead_hours"]):
        blockers.append("insufficient_incident_lead_time")
    if snapshot.get("status") != "complete":
        blockers.append(f"snapshot_status:{snapshot.get('status', 'missing')}")
    if not bindings["complete"]:
        blockers.append("receipt_binding_incomplete")
    result = {
        "case_id": row["case_id"],
        "case_name": case_name,
        "chain": chain,
        "address": address,
        "program_case": bool(row.get("program_case", True)),
        "deployment_block": deployment_block,
        "deployment_timestamp": deployment_timestamp,
        "creation_tx_hash": None if pd.isna(row.get("creation_tx_hash")) else row.get("creation_tx_hash"),
        "creation_evidence_type": row.get("creation_evidence_type"),
        "prediction_cutoff_policy": config["cutoff_policy"]["rule"],
        "prediction_cutoff_target_timestamp": target_timestamp,
        "prediction_cutoff_block": cutoff_number,
        "prediction_cutoff_timestamp": int(bracket["cutoff"]["value"]["timestamp"]) if bracket["status"] == "VERIFIED" else None,
        "prediction_cutoff_block_hash": bracket["cutoff"].get("value", {}).get("hash"),
        "incident_block": incident_block,
        "incident_timestamp": incident_timestamp,
        "cutoff_lead_hours": lead_hours,
        "provider_families": sorted({provider.provider_family for provider in providers}),
        "deployment_transition": transition,
        "cutoff_search": search,
        "cutoff_bracket": bracket,
        "incident_block_consensus": incident,
        "snapshot": snapshot,
        "state_cells": cells,
        "receipt_bindings": bindings,
        "required_state_cells": list(REQUIRED_STATE_CELLS),
        "strict_snapshot_closed": not blockers,
        "blockers": sorted(set(blockers)),
        "completed_at_utc": _utc_now(),
    }
    return _attach_strict_contract_metadata(
        result,
        row=row,
        config=config,
        providers=providers,
        provider_identity=provider_identity,
        receipt_root=receipt_root,
    )


def _case_summary(result: dict[str, Any], case_path: Path) -> dict[str, Any]:
    return {
        "case_id": result["case_id"],
        "case_name": result["case_name"],
        "chain": result["chain"],
        "strict_snapshot_closed": bool(result.get("strict_snapshot_closed")),
        "prediction_cutoff_block": result.get("prediction_cutoff_block"),
        "prediction_cutoff_block_hash": result.get("prediction_cutoff_block_hash"),
        "cutoff_lead_hours": result.get("cutoff_lead_hours"),
        "blockers": result.get("blockers", []),
        "case_artifact_path": _display_path(case_path),
        "case_artifact_sha256": _sha256_file(case_path),
    }


def run(
    config_path: Path,
    run_root: Path,
    raw_root: Path,
    processed_root: Path,
    *,
    selected_case_names: set[str] | None = None,
) -> dict[str, Any]:
    config = _load_config(config_path)
    receipt_root = raw_root / "rpc_receipts"
    receipt_root.mkdir(parents=True, exist_ok=True)
    run_root.mkdir(parents=True, exist_ok=True)
    processed_root.mkdir(parents=True, exist_ok=True)

    identity = _verify_provider_identity(config)
    _atomic_json(run_root / "provider_identity_verification.json", identity)
    if not identity["complete"]:
        raise RuntimeError("provider identity evidence is incomplete")

    amended, amendment_audit = _load_amended_pilot(config)
    amended_path = processed_root / "pilot_case_queue_amended.csv"
    amended.to_csv(amended_path, index=False)
    amendment_audit.update(
        {
            "config_path": _display_path(config_path),
            "config_sha256": _sha256_file_if_present(config_path),
            "amended_csv_path": _display_path(amended_path),
            "amended_csv_sha256": _sha256_file(amended_path),
            "created_at_utc": _utc_now(),
        }
    )
    _atomic_json(run_root / "pilot_amendment_audit.json", amendment_audit)

    cases: list[dict[str, Any]] = []
    for row in amended.to_dict(orient="records"):
        case_name = str(row["case_name"]).lower()
        case_path = run_root / "cases" / f"{case_name}.json"
        if selected_case_names is not None and case_name not in selected_case_names:
            if not case_path.is_file():
                raise FileNotFoundError(f"cannot skip missing case artifact: {case_name}")
            existing = json.loads(case_path.read_text(encoding="utf-8"))
            cases.append(_case_summary(existing, case_path))
            continue
        print(f"pilot_case_start={case_name}", flush=True)
        cached_result = None
        if case_path.is_file():
            try:
                cached_result = json.loads(case_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                cached_result = None
        try:
            result = _run_case(
                row,
                config=config,
                provider_identity_verification=identity,
                receipt_root=receipt_root,
                cached_result=cached_result,
            )
        except Exception as exc:
            result = {
                "case_id": row["case_id"],
                "case_name": case_name,
                "chain": str(row["chain"]).lower(),
                "strict_snapshot_closed": False,
                "blockers": [f"{type(exc).__name__}: {exc}"],
                "completed_at_utc": _utc_now(),
            }
        portable = _portable(result)
        _atomic_json(case_path, portable)
        print(
            f"pilot_case_finish={case_name} strict_snapshot_closed={bool(result.get('strict_snapshot_closed'))}",
            flush=True,
        )
        cases.append(_case_summary(result, case_path))
        partial_report = {
            "status": "complete" if all(case["strict_snapshot_closed"] for case in cases) and len(cases) == 10 else "partial",
            "pilot_case_count": 10,
            "cases_attempted": len(cases),
            "strict_snapshots_closed": sum(case["strict_snapshot_closed"] for case in cases),
            "cases": cases,
            "updated_at_utc": _utc_now(),
        }
        _atomic_json(run_root / "pilot_closure_report.json", partial_report)

    report = json.loads((run_root / "pilot_closure_report.json").read_text(encoding="utf-8"))
    report.pop("report_sha256_without_self_hash", None)
    receipt_manifest = _write_receipt_manifest(receipt_root, run_root)
    protocol_ineligible = [
        case["case_name"] for case in cases if "insufficient_incident_lead_time" in case.get("blockers", [])
    ]
    access_blocked = [
        case["case_name"]
        for case in cases
        if any(
            blocker in {"receipt_binding_incomplete", "snapshot_status:partial_or_disputed"}
            for blocker in case.get("blockers", [])
        )
    ]
    report.update(
        {
            "schema_version": "chronosaudit-evidence-grade-pilot-closure-v1",
            "amendment_id": config["amendment_id"],
            "provider_identity_complete": identity["complete"],
            "required_state_cells": list(REQUIRED_STATE_CELLS),
            "canonical_program_case_count_unchanged": True,
            "scientific_counter_rule": "Section 6 strict historical-snapshot evidence contract",
            "receipt_manifest_path": _display_path(run_root / "rpc_receipt_manifest.json"),
            "receipt_manifest_sha256": _sha256_file(run_root / "rpc_receipt_manifest.json"),
            "receipt_count": receipt_manifest["receipt_count"],
            "all_receipt_content_addresses_valid": receipt_manifest["all_content_addresses_valid"],
            "protocol_ineligible_cases": protocol_ineligible,
            "archive_access_blocked_cases": access_blocked,
            "release_eligible": False,
            "disposition": (
                "COMPLETE"
                if report["status"] == "complete"
                else "BLOCKED_PROTOCOL_AND_ARCHIVE_ACCESS"
                if protocol_ineligible and access_blocked
                else "BLOCKED_PROTOCOL"
                if protocol_ineligible
                else "BLOCKED_ARCHIVE_ACCESS"
            ),
        }
    )
    report["report_sha256_without_self_hash"] = _sha256_json(report)
    _atomic_json(run_root / "pilot_closure_report.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the fail-closed ChronosAudit evidence-grade pilot amendment")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--processed-root", type=Path, default=DEFAULT_PROCESSED_ROOT)
    parser.add_argument("--case", action="append", default=None, help="rerun only this case name; may be repeated")
    args = parser.parse_args()
    selected = {value.strip().lower() for value in args.case} if args.case else None
    report = run(
        args.config.resolve(),
        args.run_root.resolve(),
        args.raw_root.resolve(),
        args.processed_root.resolve(),
        selected_case_names=selected,
    )
    print(json.dumps({key: report[key] for key in ("status", "pilot_case_count", "cases_attempted", "strict_snapshots_closed")}, sort_keys=True))
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
