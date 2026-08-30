from __future__ import annotations

import ast
import hashlib
import json
import string
from datetime import datetime, timezone
from typing import Any, Iterable

import pandas as pd

SUPPORTED_CHAINS = {"ethereum": 1, "bsc": 56, "base": 8453, "arbitrum": 42161}
DEFAULT_SUPPORTED_CHAINS = tuple(SUPPORTED_CHAINS.keys())
EXTERNAL_CREATION_PROOF_TYPES = {
    "transaction",
    "transaction_receipt",
    "receipt",
    "archive_receipt",
    "explorer_receipt",
    "receipt_and_block_hash",
}
INTERNAL_CREATION_PROOF_TYPES = {
    "trace",
    "transaction_and_trace",
}
REQUIRED_OUTPUT_COLUMNS = [
    "deployment_id",
    "chain",
    "chain_id",
    "contract_address",
    "creation_tx_hash",
    "creation_type",
    "deployment_block",
    "deployment_block_hash",
    "deployment_time",
    "creator_address",
    "runtime_code_sha256",
    "source_provider",
    "source_object_key",
    "source_object_etag",
    "source_record_sha256",
    "duplicate_group_id",
    "admissibility_status",
    "exclusion_reason",
    "selection_rank_sha256",
]


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_supported_chains(chains: Iterable[str] | None) -> tuple[str, ...]:
    values = tuple(DEFAULT_SUPPORTED_CHAINS if chains is None else (str(chain).strip().lower() for chain in chains))
    if not values:
        raise ValueError("supported chains must be non-empty")
    for chain in values:
        if chain not in SUPPORTED_CHAINS:
            raise ValueError(f"unsupported chain in supported set: {chain}")
    return values


def _normalize_chain(value: Any) -> str:
    chain = str(value).strip().lower()
    if chain not in SUPPORTED_CHAINS:
        raise ValueError(f"unsupported chain: {value}")
    return chain


def _normalize_chain_id(chain: str, value: Any) -> int:
    if value is None or pd.isna(value):
        return SUPPORTED_CHAINS[chain]
    chain_id = int(value)
    if chain_id != SUPPORTED_CHAINS[chain]:
        raise ValueError(f"chain_id mismatch for {chain}: {value}")
    return chain_id


def _coerce_hex_identifier(value: Any, *, expected_hex_chars: int, field_name: str) -> str | None:
    if value is None or pd.isna(value):
        return None

    def _validate(text: str) -> str:
        candidate = text.strip().lower()
        if candidate.startswith("0x"):
            candidate = candidate[2:]
        if len(candidate) != expected_hex_chars or any(ch not in string.hexdigits for ch in candidate):
            raise ValueError(f"invalid {field_name}: {value}")
        return "0x" + candidate

    def _from_bytes(raw: bytes) -> str:
        try:
            decoded = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            decoded = ""
        if decoded:
            try:
                return _validate(decoded)
            except ValueError:
                pass
        return _validate(raw.hex())

    if isinstance(value, memoryview):
        return _from_bytes(value.tobytes())
    if isinstance(value, bytearray):
        return _from_bytes(bytes(value))
    if isinstance(value, bytes):
        return _from_bytes(value)

    text = str(value).strip()
    if text.startswith(("b'", 'b"')):
        try:
            literal = ast.literal_eval(text)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"invalid {field_name}: {value}") from exc
        if isinstance(literal, str):
            return _validate(literal)
        if isinstance(literal, (bytes, bytearray)):
            return _from_bytes(bytes(literal))
        raise ValueError(f"invalid {field_name}: {value}")
    return _validate(text)


def _normalize_address(value: Any) -> str | None:
    return _coerce_hex_identifier(value, expected_hex_chars=40, field_name="address")


def _normalize_tx_hash(value: Any) -> str | None:
    return _coerce_hex_identifier(value, expected_hex_chars=64, field_name="transaction hash")


def _normalize_block_hash(value: Any) -> str | None:
    if value is None or pd.isna(value):
        return None
    block_hash = str(value).strip().lower()
    if not block_hash.startswith("0x") or len(block_hash) != 66:
        raise ValueError(f"invalid block hash: {value}")
    return block_hash


def _normalize_sha256(value: Any) -> str | None:
    if value is None or pd.isna(value):
        return None
    digest = str(value).strip().lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError(f"invalid sha256 digest: {value}")
    return digest


def _duplicate_group_id(row: dict[str, Any]) -> str:
    material = "|".join(
        [
            row["chain"],
            row["contract_address"] or "",
            row["creation_tx_hash"] or "",
            row["runtime_code_sha256"] or "",
        ]
    )
    return _sha256_text(material)


def _deployment_id(row: dict[str, Any]) -> str:
    existing = row.get("deployment_id")
    if existing:
        return str(existing)
    material = "|".join(
        [
            row["chain"],
            str(row["chain_id"]),
            row["contract_address"] or "",
            row["creation_tx_hash"] or "",
            str(row["deployment_block"] or ""),
        ]
    )
    return "dep-" + _sha256_text(material)


def _normalize_creation_type(value: Any) -> str:
    creation_type = str(value or "").strip().lower()
    return creation_type or "unknown"


def _creation_proof_status(raw: dict[str, Any], creation_type: str, creation_tx_hash: str | None) -> str | None:
    proof_type = str(raw.get("creation_proof_type") or "").strip().lower()
    trace_proof = bool(raw.get("trace_proof"))
    if creation_type == "current_code_only" or creation_tx_hash is None:
        return "missing_creation_proof"
    if creation_type.startswith("internal"):
        if proof_type and proof_type not in INTERNAL_CREATION_PROOF_TYPES:
            return "invalid_creation_proof_type"
        if not (trace_proof or proof_type in INTERNAL_CREATION_PROOF_TYPES):
            return "missing_trace_creation_proof"
        return None
    if proof_type == "":
        return "missing_creation_proof"
    if proof_type not in EXTERNAL_CREATION_PROOF_TYPES:
        return "invalid_creation_proof_type"
    return None


def _selection_rank(chain: str, deployment_id: str, seed: str, purpose: str) -> str:
    return _sha256_text(f"{seed}|{purpose}|{chain}|{deployment_id}")


def normalize_deployment_batch(rows: pd.DataFrame | list[dict[str, Any]]) -> pd.DataFrame:
    frame = rows.copy() if isinstance(rows, pd.DataFrame) else pd.DataFrame(rows)
    if frame.empty:
        return pd.DataFrame(columns=REQUIRED_OUTPUT_COLUMNS)

    normalized_rows: list[dict[str, Any]] = []
    for raw in frame.to_dict(orient="records"):
        chain = _normalize_chain(raw["chain"])
        row = {
            "chain": chain,
            "chain_id": _normalize_chain_id(chain, raw.get("chain_id")),
            "contract_address": _normalize_address(raw.get("contract_address")),
            "creation_tx_hash": _normalize_tx_hash(raw.get("creation_tx_hash")),
            "creation_type": _normalize_creation_type(raw.get("creation_type")),
            "deployment_block": None if pd.isna(raw.get("deployment_block")) else int(raw.get("deployment_block")),
            "deployment_block_hash": _normalize_block_hash(raw.get("deployment_block_hash")),
            "deployment_time": None if pd.isna(raw.get("deployment_time")) else str(raw.get("deployment_time")),
            "creator_address": _normalize_address(raw.get("creator_address")),
            "runtime_code_sha256": _normalize_sha256(raw.get("runtime_code_sha256")),
            "source_provider": str(raw.get("source_provider") or "").strip(),
            "source_object_key": str(raw.get("source_object_key") or "").strip(),
            "source_object_etag": str(raw.get("source_object_etag") or "").strip(),
            "source_record_sha256": _normalize_sha256(raw.get("source_record_sha256")),
        }
        row["duplicate_group_id"] = _duplicate_group_id(row)
        row["deployment_id"] = _deployment_id({**raw, **row})
        row["selection_rank_sha256"] = None

        exclusion_reason = _creation_proof_status(raw, row["creation_type"], row["creation_tx_hash"])
        if exclusion_reason is None and row["deployment_block"] is None:
            exclusion_reason = "missing_deployment_block"
        if exclusion_reason is None and not row["deployment_time"]:
            exclusion_reason = "missing_deployment_timestamp"
        if exclusion_reason is None and (not row["source_provider"] or not row["source_object_key"] or not row["source_record_sha256"]):
            exclusion_reason = "missing_source_record"

        row["admissibility_status"] = "EXCLUDED" if exclusion_reason else "VERIFIED"
        row["exclusion_reason"] = exclusion_reason
        normalized_rows.append(row)

    normalized = pd.DataFrame(normalized_rows)
    verified = normalized[normalized["admissibility_status"] == "VERIFIED"].copy()
    if not verified.empty:
        verified = verified.sort_values(["duplicate_group_id", "source_record_sha256", "source_object_key", "source_object_etag"])
        duplicate_indexes = verified.duplicated(subset=["duplicate_group_id"], keep="first")
        duplicate_row_indexes = verified.loc[duplicate_indexes].index
        normalized.loc[duplicate_row_indexes, "admissibility_status"] = "EXCLUDED"
        normalized.loc[duplicate_row_indexes, "exclusion_reason"] = "duplicate_record"

    normalized = normalized.loc[:, REQUIRED_OUTPUT_COLUMNS].copy()
    return normalized.sort_values(["chain", "deployment_id"]).reset_index(drop=True)


def _empty_audit_frame() -> pd.DataFrame:
    return pd.DataFrame(
        columns=[
            "chain",
            "inventory_rows",
            "parsed_rows",
            "verified_rows",
            "duplicates",
            "exclusions",
            "available",
            "selected",
            "shortfall",
        ]
    )


def select_denominator(
    deployments: pd.DataFrame | list[dict[str, Any]],
    *,
    per_chain: int,
    seed: str,
    supported_chains: Iterable[str] | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    supported = _normalize_supported_chains(supported_chains)
    frame = deployments.copy() if isinstance(deployments, pd.DataFrame) else pd.DataFrame(deployments)

    selected_frames: list[pd.DataFrame] = []
    audit_rows: list[dict[str, Any]] = []
    for chain in supported:
        chain_frame = frame[frame["chain"] == chain].copy() if not frame.empty else pd.DataFrame(columns=REQUIRED_OUTPUT_COLUMNS)
        verified = chain_frame[chain_frame["admissibility_status"] == "VERIFIED"].copy() if not chain_frame.empty else pd.DataFrame(columns=REQUIRED_OUTPUT_COLUMNS)
        if not verified.empty:
            verified["selection_rank_sha256"] = verified["deployment_id"].map(
                lambda deployment_id: _selection_rank(chain, str(deployment_id), seed, "denominator")
            )
            verified = verified.sort_values(["selection_rank_sha256", "deployment_id"]).reset_index(drop=True)
        available = len(verified)
        selected_count = min(per_chain, available)
        if selected_count:
            selected_frames.append(verified.head(selected_count))
        audit_rows.append(
            {
                "chain": chain,
                "inventory_rows": len(chain_frame),
                "parsed_rows": len(chain_frame),
                "verified_rows": available,
                "duplicates": int(chain_frame["exclusion_reason"].fillna("").eq("duplicate_record").sum()) if not chain_frame.empty else 0,
                "exclusions": int(chain_frame["admissibility_status"].ne("VERIFIED").sum()) if not chain_frame.empty else 0,
                "available": available,
                "selected": selected_count,
                "shortfall": per_chain - selected_count,
            }
        )

    selected = pd.concat(selected_frames, ignore_index=True) if selected_frames else pd.DataFrame(columns=REQUIRED_OUTPUT_COLUMNS)
    audit = pd.DataFrame(audit_rows).sort_values("chain").reset_index(drop=True) if audit_rows else _empty_audit_frame()
    return selected.loc[:, REQUIRED_OUTPUT_COLUMNS].copy(), audit


def _build_crosscheck_manifest(selected: pd.DataFrame, crosscheck_per_chain: int, seed: str) -> pd.DataFrame:
    manifests: list[pd.DataFrame] = []
    counts = selected.groupby("chain").size().to_dict()
    for chain in sorted(counts):
        chain_rows = selected[selected["chain"] == chain].copy()
        chain_rows["crosscheck_rank_sha256"] = chain_rows["deployment_id"].map(
            lambda deployment_id: _selection_rank(chain, str(deployment_id), seed, "crosscheck")
        )
        chain_rows = chain_rows.sort_values(["crosscheck_rank_sha256", "deployment_id"]).reset_index(drop=True)
        manifests.append(chain_rows.head(min(crosscheck_per_chain, len(chain_rows))))
    return pd.concat(manifests, ignore_index=True) if manifests else pd.DataFrame()


def _manifest_sha256(frame: pd.DataFrame) -> str:
    if frame.empty:
        return _sha256_text("[]")
    payload = frame.sort_values(["chain", "deployment_id"]).to_dict(orient="records")
    return _sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _normalize_crosscheck_status(value: Any) -> str:
    status = str(value or "").strip().upper()
    if status not in {"VERIFIED", "PARTIAL", "DISPUTED"}:
        raise ValueError(f"unsupported adjudication status: {value}")
    return status


def _candidate_pool_frame(candidate_pool: pd.DataFrame | None, selected: pd.DataFrame, seed: str) -> pd.DataFrame:
    frame = (candidate_pool.copy() if candidate_pool is not None else selected.copy()).reset_index(drop=True)
    if frame.empty:
        return frame
    if "selection_rank_sha256" not in frame.columns:
        frame["selection_rank_sha256"] = None
    for index, row in frame.iterrows():
        if not str(row.get("selection_rank_sha256") or "").strip():
            frame.loc[index, "selection_rank_sha256"] = _selection_rank(str(row["chain"]), str(row["deployment_id"]), seed, "denominator")
    return frame


def validate_denominator(
    selected: pd.DataFrame,
    audit: pd.DataFrame,
    *,
    per_chain: int,
    crosscheck_per_chain: int = 50,
    seed: str,
    expected_chains: Iterable[str] | None = None,
    candidate_pool: pd.DataFrame | None = None,
    crosscheck_results: pd.DataFrame | None = None,
    frozen: bool = False,
) -> dict[str, Any]:
    expected = _normalize_supported_chains(expected_chains)
    working_selected = selected.copy()
    working_audit = audit.copy()
    errors: list[str] = []
    replacement_log: list[dict[str, Any]] = []
    adjudication_log: list[dict[str, Any]] = []

    if working_selected.empty:
        errors.append("selected denominator is empty")

    if not working_selected.empty and not working_selected["admissibility_status"].eq("VERIFIED").all():
        errors.append("selected denominator contains non-VERIFIED rows")

    audit_chains = set(working_audit["chain"].tolist()) if not working_audit.empty else set()
    for chain in expected:
        if chain not in audit_chains:
            errors.append(f"missing_expected_chain:{chain}")

    counts = working_selected.groupby("chain").size().to_dict() if not working_selected.empty else {}
    for chain in expected:
        count = int(counts.get(chain, 0))
        if count > per_chain:
            errors.append(f"{chain} exceeds per-chain limit {per_chain}")
        matching = working_audit[working_audit["chain"] == chain] if not working_audit.empty else pd.DataFrame()
        if not matching.empty and int(matching.iloc[0]["selected"]) != count:
            errors.append(f"{chain} selected count does not match audit")

    candidate_frame = _candidate_pool_frame(candidate_pool, working_selected, seed)
    quarantine_ids = set(candidate_frame.loc[candidate_frame["admissibility_status"] != "VERIFIED", "deployment_id"].astype(str).tolist())
    if crosscheck_results is not None and not crosscheck_results.empty:
        quarantine_ids.update(
            str(row["deployment_id"])
            for row in crosscheck_results.to_dict(orient="records")
            if _normalize_crosscheck_status(row.get("adjudication_status")) != "VERIFIED"
        )
    manifest_before = _build_crosscheck_manifest(working_selected, crosscheck_per_chain, seed)
    manifest_sha256 = _manifest_sha256(manifest_before)

    if crosscheck_results is not None and not crosscheck_results.empty:
        for row in crosscheck_results.to_dict(orient="records"):
            deployment_id = str(row["deployment_id"])
            status = _normalize_crosscheck_status(row.get("adjudication_status"))
            reason = str(row.get("reason") or "").strip()
            if status == "VERIFIED":
                continue

            match = working_selected[working_selected["deployment_id"] == deployment_id]
            if match.empty:
                errors.append(f"crosscheck_result_not_in_selected:{deployment_id}")
                continue

            failed_row = match.iloc[0].to_dict()
            adjudication_log.append(
                {
                    "deployment_id": deployment_id,
                    "chain": failed_row["chain"],
                    "admissibility_status": status,
                    "reason": reason,
                    "observed_at_utc": _now_utc(),
                }
            )

            if frozen:
                errors.append(f"frozen_denominator_crosscheck_failure:{deployment_id}:{status}")
                continue

            chain = str(failed_row["chain"])
            current_ids = set(working_selected["deployment_id"].tolist())
            quarantine_ids.add(deployment_id)
            eligible_replacements = candidate_frame[
                (candidate_frame["chain"] == chain)
                & (candidate_frame["admissibility_status"] == "VERIFIED")
                & (~candidate_frame["deployment_id"].isin(current_ids))
                & (~candidate_frame["deployment_id"].isin(quarantine_ids))
            ].copy()
            eligible_replacements = eligible_replacements.sort_values(["selection_rank_sha256", "deployment_id"]).reset_index(drop=True)
            if eligible_replacements.empty:
                errors.append(f"no_replacement_available:{deployment_id}")
                continue

            replacement = eligible_replacements.iloc[0].to_dict()
            working_selected = working_selected[working_selected["deployment_id"] != deployment_id].copy()
            working_selected = pd.concat([working_selected, pd.DataFrame([replacement])], ignore_index=True)
            working_selected = working_selected.sort_values(["chain", "selection_rank_sha256", "deployment_id"]).reset_index(drop=True)
            replacement_log.append(
                {
                    "failed_deployment_id": deployment_id,
                    "failed_selection_rank_sha256": failed_row.get("selection_rank_sha256"),
                    "crosscheck_status": status,
                    "reason": reason,
                    "replacement_deployment_id": replacement["deployment_id"],
                    "replacement_selection_rank_sha256": replacement["selection_rank_sha256"],
                    "logged_at_utc": _now_utc(),
                    "crosscheck_manifest_sha256": manifest_sha256,
                }
            )

    final_counts = working_selected.groupby("chain").size().to_dict() if not working_selected.empty else {}
    for chain in expected:
        matching = working_audit[working_audit["chain"] == chain]
        if matching.empty:
            continue
        working_audit.loc[matching.index, "selected"] = int(final_counts.get(chain, 0))
        working_audit.loc[matching.index, "shortfall"] = per_chain - int(final_counts.get(chain, 0))

    crosscheck_manifest = _build_crosscheck_manifest(working_selected, crosscheck_per_chain, seed)
    return {
        "valid": not errors,
        "errors": errors,
        "selected": working_selected.loc[:, REQUIRED_OUTPUT_COLUMNS].copy() if not working_selected.empty else pd.DataFrame(columns=REQUIRED_OUTPUT_COLUMNS),
        "audit": working_audit.sort_values("chain").reset_index(drop=True) if not working_audit.empty else _empty_audit_frame(),
        "crosscheck_manifest": crosscheck_manifest,
        "replacement_log": replacement_log,
        "adjudication_log": adjudication_log,
    }


__all__ = [
    "normalize_deployment_batch",
    "select_denominator",
    "validate_denominator",
]
