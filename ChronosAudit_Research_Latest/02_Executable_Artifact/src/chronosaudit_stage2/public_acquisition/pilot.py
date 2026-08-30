from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

import pandas as pd

from chronosaudit_stage2.onchain import JsonRpcProvider, provider_consensus

from .strict_snapshot import (
    first_block_at_or_after_timestamp as _first_block_at_or_after_timestamp,
    snapshot_state_cells as _snapshot_state_cells,
    verify_cutoff_block_bracket as _verify_cutoff_block_bracket,
    verify_snapshot_receipt_bindings as _verify_snapshot_receipt_bindings,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_TX_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return bool(_SHA256_RE.fullmatch(str(value or "").strip().lower()))


def _eligible_candidate(row: pd.Series) -> bool:
    return bool(
        str(row.get("eligibility_status", "")).strip().upper() == "VERIFIED"
        and str(row.get("chain", "")).strip().lower() == "arbitrum"
        and _ADDRESS_RE.fullmatch(str(row.get("address", "")).strip().lower())
        and _TX_HASH_RE.fullmatch(str(row.get("exploit_tx_hash", "")).strip().lower())
        and pd.notna(row.get("incident_block"))
        and pd.notna(row.get("prediction_cutoff_block"))
        and _is_sha256(row.get("candidate_source_sha256"))
    )


def build_postfreeze_pilot_amendment(
    base_pilot: pd.DataFrame,
    candidates: pd.DataFrame,
    *,
    seed: str,
    base_manifest_sha256: str,
    amendment_id: str,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Add one pre-screened Arbitrum case without rewriting the frozen nine-case pilot.

    The supplement is deliberately outside the canonical 417-case program corpus. It
    repairs only the pilot allocation shortfall and is labelled as a post-freeze
    amendment so that observed provider outcomes cannot be mistaken for the original
    selection process.
    """
    if len(base_pilot) != 9:
        raise ValueError(f"post-freeze amendment requires the preserved nine-case pilot, found {len(base_pilot)}")
    if not _is_sha256(base_manifest_sha256):
        raise ValueError("base_manifest_sha256 must be a sha256 digest")
    if not seed.strip() or not amendment_id.strip():
        raise ValueError("seed and amendment_id must be non-empty")

    eligible = candidates.loc[candidates.apply(_eligible_candidate, axis=1)].copy()
    if eligible.empty:
        raise ValueError("no eligible Arbitrum supplement candidate")
    eligible["supplement_rank_sha256"] = eligible.apply(
        lambda row: _sha256_text(
            "|".join(
                [
                    seed,
                    "pilot-supplement",
                    str(row["chain"]).strip().lower(),
                    str(row["case_name"]).strip().lower(),
                    str(row["address"]).strip().lower(),
                    str(int(row["incident_block"])),
                ]
            )
        ),
        axis=1,
    )
    selected = eligible.sort_values(["supplement_rank_sha256", "case_id"]).iloc[0].to_dict()

    base = base_pilot.copy()
    base["program_case"] = True
    base["pilot_selection_origin"] = "frozen_original"
    base["pilot_amendment_id"] = amendment_id
    base["base_manifest_sha256"] = base_manifest_sha256.lower()

    supplement = {column: pd.NA for column in base.columns}
    supplement.update(selected)
    supplement.update(
        {
            "pilot_member": True,
            "program_case": False,
            "pilot_selection_origin": "postfreeze_shortfall_amendment",
            "pilot_amendment_id": amendment_id,
            "base_manifest_sha256": base_manifest_sha256.lower(),
        }
    )
    amended = pd.concat([base, pd.DataFrame([supplement])], ignore_index=True, sort=False)
    counts = amended["chain"].astype(str).str.lower().value_counts().to_dict()
    expected = {"ethereum": 3, "bsc": 3, "base": 2, "arbitrum": 2}
    if counts != expected:
        raise ValueError(f"amended pilot allocation mismatch: {counts}")
    if amended["case_id"].astype(str).duplicated().any():
        raise ValueError("amended pilot contains duplicate case IDs")

    manifest_rows = amended.fillna("").sort_values(["chain", "case_id"]).to_dict(orient="records")
    audit = {
        "amendment_id": amendment_id,
        "amendment_type": "postfreeze_pilot_shortfall_only",
        "base_manifest_sha256": base_manifest_sha256.lower(),
        "original_case_count": 9,
        "amended_case_count": 10,
        "original_shortfall_preserved": True,
        "canonical_program_case_count_unchanged": True,
        "selection_observed_provider_results": False,
        "selection_seed": seed,
        "eligible_candidate_count": int(len(eligible)),
        "selected_case_id": str(selected["case_id"]),
        "selected_rank_sha256": str(selected["supplement_rank_sha256"]),
        "amended_manifest_sha256": _sha256_text(_canonical_json(manifest_rows)),
    }
    return amended, audit


def apply_prespecified_pilot_replacement(
    pilot: pd.DataFrame,
    replacement: dict[str, Any],
    *,
    failed_case_name: str,
    failure_reason: str,
    seed: str,
    amendment_id: str,
    parent_manifest_sha256: str,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Replace one protocol-ineligible pilot case under an outcome-blind rule.

    This is a new, explicit amendment rather than a mutation of the parent pilot.
    The replacement must be fully identified from preserved incident evidence before
    its RPC acquisition begins. A failed replacement is not silently substituted.
    """
    if len(pilot) != 10:
        raise ValueError(f"replacement amendment requires a ten-case parent pilot, found {len(pilot)}")
    if not _is_sha256(parent_manifest_sha256):
        raise ValueError("parent_manifest_sha256 must be a sha256 digest")
    if not seed.strip() or not amendment_id.strip() or not failure_reason.strip():
        raise ValueError("seed, amendment_id, and failure_reason must be non-empty")

    failed = failed_case_name.strip().lower()
    names = pilot["case_name"].astype(str).str.strip().str.lower()
    if int(names.eq(failed).sum()) != 1:
        raise ValueError("failed case must identify exactly one parent pilot row")

    candidate = pd.Series(replacement)
    if not _eligible_candidate(candidate):
        raise ValueError("replacement candidate is not independently eligible")
    selected_case_id = str(replacement.get("case_id", "")).strip()
    selected_case_name = str(replacement.get("case_name", "")).strip().lower()
    if not selected_case_id or not selected_case_name:
        raise ValueError("replacement candidate requires case_id and case_name")
    if selected_case_id in set(pilot["case_id"].astype(str)) or selected_case_name in set(names):
        raise ValueError("replacement candidate duplicates the parent pilot")

    amended = pilot.loc[~names.eq(failed)].copy()
    row = {column: pd.NA for column in amended.columns}
    row.update(replacement)
    row.update(
        {
            "pilot_member": True,
            "program_case": False,
            "pilot_selection_origin": "prespecified_protocol_replacement",
            "pilot_amendment_id": amendment_id,
            "base_manifest_sha256": parent_manifest_sha256.lower(),
        }
    )
    amended = pd.concat([amended, pd.DataFrame([row])], ignore_index=True, sort=False)
    if len(amended) != 10 or amended["case_id"].astype(str).duplicated().any():
        raise ValueError("replacement amendment did not preserve ten unique cases")

    rank_sha256 = _sha256_text(
        "|".join(
            [
                seed,
                "protocol-replacement",
                failed,
                selected_case_name,
                str(replacement["address"]).strip().lower(),
                str(int(replacement["incident_block"])),
            ]
        )
    )
    amended.loc[amended["case_name"].astype(str).str.lower().eq(selected_case_name), "supplement_rank_sha256"] = rank_sha256
    manifest_rows = amended.fillna("").sort_values(["chain", "case_id"]).to_dict(orient="records")
    audit = {
        "amendment_id": amendment_id,
        "amendment_type": "prespecified_protocol_ineligible_case_replacement",
        "parent_manifest_sha256": parent_manifest_sha256.lower(),
        "parent_case_count": 10,
        "amended_case_count": 10,
        "replaced_case_name": failed,
        "replacement_trigger": failure_reason,
        "selection_observed_replacement_provider_results": False,
        "no_reselection_after_provider_observation": True,
        "selection_seed": seed,
        "selected_case_id": selected_case_id,
        "selected_rank_sha256": rank_sha256,
        "canonical_program_case_count_unchanged": True,
        "amended_manifest_sha256": _sha256_text(_canonical_json(manifest_rows)),
    }
    return amended, audit


def verify_snapshot_receipt_bindings(
    cells: dict[str, dict[str, Any]],
    *,
    required_cells: Iterable[str],
    allowed_root: str | Path,
) -> dict[str, Any]:
    adapted: dict[str, dict[str, Any]] = {}
    for cell_name, cell in cells.items():
        current = dict(cell)
        observations = []
        for observation in current.get("observations", []):
            item = dict(observation)
            if "block_selector" not in item:
                params = list(item.get("params", []))
                method = str(item.get("method", "")).strip()
                item["block_selector"] = (
                    params[0]
                    if method == "eth_getBlockByNumber" and params
                    else (params[-1] if params else None)
                )
            item.setdefault("provider_identity", str(item.get("provider_id", "")))
            item.setdefault("observed_at_utc", "1970-01-01T00:00:00Z")
            observations.append(item)
        current["observations"] = observations
        adapted[cell_name] = current
    verified = _verify_snapshot_receipt_bindings(
        adapted,
        required_cells=tuple(required_cells),
        allowed_root=allowed_root,
    )
    for detail in verified["cells"].values():
        errors = list(detail.get("errors", []))
        if "same_provider_family" in errors and "insufficient_independent_provider_families" not in errors:
            errors.append("insufficient_independent_provider_families")
        detail["errors"] = errors
    return verified


def first_block_at_or_after_timestamp(
    provider: JsonRpcProvider,
    *,
    target_timestamp: int,
    lower_block: int,
    upper_block: int,
) -> dict[str, Any]:
    return _first_block_at_or_after_timestamp(
        provider,
        target_timestamp=target_timestamp,
        lower_block=lower_block,
        upper_block=upper_block,
    )


def verify_cutoff_block_bracket(
    providers: list[JsonRpcProvider],
    *,
    target_timestamp: int,
    previous_block_number: int,
    cutoff_block_number: int,
) -> dict[str, Any]:
    return _verify_cutoff_block_bracket(
        providers,
        target_timestamp=target_timestamp,
        previous_block_number=previous_block_number,
        cutoff_block_number=cutoff_block_number,
        consensus_fn=provider_consensus,
    )


def snapshot_state_cells(
    snapshot: dict[str, Any],
    *,
    providers: list[JsonRpcProvider],
) -> dict[str, dict[str, Any]]:
    return _snapshot_state_cells(snapshot, providers=providers, consensus_fn=provider_consensus)


__all__ = [
    "build_postfreeze_pilot_amendment",
    "first_block_at_or_after_timestamp",
    "snapshot_state_cells",
    "verify_cutoff_block_bracket",
    "verify_snapshot_receipt_bindings",
]
