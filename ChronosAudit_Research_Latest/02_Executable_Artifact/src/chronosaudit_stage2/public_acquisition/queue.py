from __future__ import annotations

import hashlib
import json
from typing import Any

import pandas as pd

SELECTION_CODE_VERSION = "chronosaudit-public-queue-v1"
CHAIN_ALIASES = {
    "mainnet": "ethereum",
    "eth": "ethereum",
    "arb": "arbitrum",
    "arbi": "arbitrum",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_sha256(name: str, value: str) -> str:
    normalized = str(value).strip().lower()
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise ValueError(f"{name} must be a 64-character sha256 hex digest")
    return normalized


def _normalize_chain(value: Any) -> str:
    normalized = str(value).strip().lower()
    normalized = CHAIN_ALIASES.get(normalized, normalized)
    if normalized not in {"ethereum", "bsc", "base", "arbitrum"}:
        raise ValueError(f"unsupported chain: {value}")
    return normalized


def _normalize_address(value: Any) -> str:
    text = str(value).strip().lower()
    if not text.startswith("0x") or len(text) != 42:
        raise ValueError(f"invalid address: {value}")
    return text


def _case_id(row: pd.Series) -> str:
    if "case_id" in row and pd.notna(row["case_id"]) and str(row["case_id"]).strip():
        return str(row["case_id"]).strip()
    material = f"{row['case_name']}|{row['chain']}|{row['address']}|{int(row['incident_block'])}"
    return "ca2-" + _sha256_text(material)[:20]


def _proxy_hint(row: pd.Series) -> bool:
    if "proxy_type" in row and pd.notna(row["proxy_type"]) and str(row["proxy_type"]).strip():
        return True
    queries = str(row.get("required_queries", "") or "").lower()
    return "eip-1967" in queries or "proxy" in queries or "beacon" in queries


def _age_strata(group: pd.DataFrame) -> pd.Series:
    if len(group) == 1:
        return pd.Series([0], index=group.index, dtype="int64")
    ranks = group["incident_block"].rank(method="first")
    quantiles = min(4, len(group))
    return pd.qcut(ranks, q=quantiles, labels=False, duplicates="drop").astype("int64")


def _frame_sha256(frame: pd.DataFrame) -> str:
    payload = frame.sort_values(["case_name", "chain", "address"]).to_dict(orient="records")
    return _sha256_text(_canonical_json(payload))


def _is_verified_status(value: Any) -> bool:
    return str(value or "").strip().upper() == "VERIFIED"


def _compute_cutoff_status(row: pd.Series) -> str:
    temporal_status = str(row.get("temporal_certification", "") or "").strip().lower()
    if temporal_status.startswith("blocked_"):
        return "PARTIAL"

    required_presence = (
        pd.notna(row.get("deployment_block"))
        and pd.notna(row.get("prediction_cutoff_block"))
        and pd.notna(row.get("source_availability_time"))
    )
    if not required_presence:
        return "PARTIAL"

    explicit_verification = all(
        [
            _is_verified_status(row.get("deployment_verification_status")),
            _is_verified_status(row.get("prediction_cutoff_block_verification_status")),
            _is_verified_status(row.get("source_availability_verification_status")),
        ]
    )
    if not explicit_verification:
        return "PARTIAL"

    try:
        lead_hours = float(row.get("cutoff_lead_hours"))
    except (TypeError, ValueError):
        return "PARTIAL"

    incident_eligibility = row.get("incident_eligibility")
    if pd.isna(incident_eligibility):
        return "PARTIAL"

    return "VERIFIED" if bool(incident_eligibility) and lead_hours >= 1.0 else "PARTIAL"


def build_case_queue(
    cases: pd.DataFrame,
    policy: dict[str, Any],
    *,
    input_sha256: str,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    frame = cases.copy()
    if frame.empty:
        raise ValueError("canonical cases must not be empty")

    if "case_name" not in frame.columns:
        raise ValueError("canonical cases must include case_name")

    chain_source = "chain" if "chain" in frame.columns else "incident_chain"
    address_source = "target_contract_address" if "target_contract_address" in frame.columns else "contract_address"
    incident_source = "fork_block_number" if "fork_block_number" in frame.columns else "incident_block_or_time"

    frame["chain"] = frame[chain_source].map(_normalize_chain)
    frame["address"] = frame[address_source].map(_normalize_address)
    frame["incident_block"] = pd.to_numeric(frame[incident_source], errors="coerce").astype("Int64")
    if frame["incident_block"].isna().any():
        raise ValueError("incident_block must be resolvable before queue construction")

    if "prediction_cutoff_block" in frame.columns:
        frame["prediction_cutoff_block"] = pd.to_numeric(frame["prediction_cutoff_block"], errors="coerce").astype("Int64")
    else:
        frame["prediction_cutoff_block"] = pd.Series([pd.NA] * len(frame), dtype="Int64")

    if "deployment_block" in frame.columns:
        frame["deployment_block"] = pd.to_numeric(frame["deployment_block"], errors="coerce").astype("Int64")
    else:
        frame["deployment_block"] = pd.Series([pd.NA] * len(frame), dtype="Int64")

    frame["cutoff_status"] = frame.apply(_compute_cutoff_status, axis=1)
    frame["proxy_hint"] = frame.apply(_proxy_hint, axis=1)

    frame["case_id"] = frame.apply(_case_id, axis=1)
    if frame["case_id"].duplicated().any():
        duplicates = frame.loc[frame["case_id"].duplicated(), "case_id"].tolist()
        raise ValueError(f"duplicate case_id values are not allowed: {duplicates[:3]}")

    expected_total = int(policy["full_case_target"])
    if len(frame) != expected_total:
        raise ValueError(f"expected {expected_total} canonical cases, found {len(frame)}")

    frame["age_stratum"] = (
        frame.groupby("chain", group_keys=False)
        .apply(_age_strata, include_groups=False)
        .astype("int64")
    )
    seed = str(policy["seed"])
    frame["pilot_hash"] = frame.apply(
        lambda row: _sha256_text(f"{seed}|pilot|{row['chain']}|{row['case_name']}"),
        axis=1,
    )

    pilot_indexes: list[int] = []
    allocation: dict[str, int] = dict(policy["pilot_allocation"])
    allocation_audit: dict[str, dict[str, Any]] = {}
    for chain, count in allocation.items():
        eligible = frame.loc[frame["chain"] == chain].sort_values(
            ["proxy_hint", "age_stratum", "pilot_hash", "case_id"],
            ascending=[False, True, True, True],
        )
        selected = min(len(eligible), count)
        allocation_audit[chain] = {
            "pilot_allocation_expected": count,
            "pilot_allocation_selected": selected,
            "allocation_satisfied": selected == count,
        }
        pilot_indexes.extend(eligible.head(selected).index.tolist())

    frame["pilot_member"] = frame.index.isin(pilot_indexes)
    frame["priority"] = frame["pilot_member"].map(lambda member: 0 if member else 1)
    frame["pilot_allocation_expected"] = frame["chain"].map(lambda chain: allocation_audit[chain]["pilot_allocation_expected"])
    frame["pilot_allocation_selected"] = frame["chain"].map(lambda chain: allocation_audit[chain]["pilot_allocation_selected"])
    frame["allocation_satisfied"] = frame["chain"].map(lambda chain: allocation_audit[chain]["allocation_satisfied"])
    frame["input_sha256"] = _validate_sha256("input_sha256", input_sha256)
    frame["policy_sha256"] = _sha256_text(_canonical_json(policy))

    selection_columns = [
        "case_id",
        "case_name",
        "chain",
        "address",
        "incident_block",
        "pilot_member",
        "priority",
        "cutoff_status",
        "prediction_cutoff_block",
        "pilot_allocation_expected",
        "pilot_allocation_selected",
        "allocation_satisfied",
        "input_sha256",
        "policy_sha256",
    ]
    manifest_input = frame.loc[:, selection_columns].copy()
    manifest_input["selection_code_version"] = SELECTION_CODE_VERSION
    manifest_input["seed"] = seed

    full_manifest_sha = _frame_sha256(manifest_input)
    pilot_manifest_sha = _frame_sha256(manifest_input.loc[manifest_input["pilot_member"]])
    frame["queue_sha256"] = full_manifest_sha

    full = frame.sort_values(["priority", "chain", "pilot_hash", "case_id"]).reset_index(drop=True)
    pilot = full.loc[full["pilot_member"]].copy().reset_index(drop=True)
    pilot["queue_sha256"] = pilot_manifest_sha
    return full, pilot
