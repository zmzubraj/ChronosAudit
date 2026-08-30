from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from .qualification import (
    STRICT_HISTORICAL_STATUS,
    STRICT_HUMAN_CONFIDENCE,
    make_control_row_sha256,
    qualify_control_rows,
    verify_control_cohort_structure,
    verify_release_eligibility,
)

CORE_COUNTER_KEYS = (
    "historical_snapshots",
    "independent_adjudications",
    "deployment_denominator",
    "control_candidates",
    "qualified_controls",
    "independent_r5_blocks",
    "release_eligible_cases",
)
PACKET_COUNTER_KEYS = (
    "positive_case_review_packets",
    "control_review_packets",
    "finalized_positive_adjudications",
)
COUNTER_ARTIFACT_VERSION = "2026-08-08.task5"
COUNTER_ARTIFACT_ALLOWED_KEYS = {"artifact_schema_version", "input_manifest_sha256", "counters"}
COUNTER_ALLOWED_KEYS = set(CORE_COUNTER_KEYS) | set(PACKET_COUNTER_KEYS)
DEFAULT_COUNTER_TARGETS = {
    "deployment_denominator_required": 20000,
    "deployment_denominator_per_chain": {
        "ethereum": 5000,
        "bsc": 5000,
        "base": 5000,
        "arbitrum": 5000,
    },
    "control_candidates_required": 4170,
    "qualified_controls_required": 4170,
    "independent_r5_blocks_required": 120,
}
COUNTER_TARGET_KEYS = tuple(DEFAULT_COUNTER_TARGETS.keys())
_REVIEW_VISIBLE_FIELDS = [
    "case_name",
    "incident_name",
    "chain",
    "target_contract_address",
    "incident_date",
]
HISTORICAL_SNAPSHOT_OVERLAY_FIELDS = (
    "historical_snapshot_status",
    "historical_snapshot_source_receipt_sha256",
    "historical_snapshot_identity_receipt_sha256",
    "historical_snapshot_source_provider_family",
    "historical_snapshot_identity_provider_family",
    "historical_snapshot_schema_valid",
    "historical_snapshot_hash_bound",
)
_HISTORICAL_SNAPSHOT_IDENTIFIER_FIELDS = ("case_id", "case_name")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def canonical_manifest_sha256(value: dict[str, Any]) -> str:
    payload = {
        key: value[key]
        for key in sorted(value.keys())
        if key not in {"input_manifest_sha256", "self_sha256"}
    }
    return _sha256_json(payload)


def make_independent_adjudication_binding_sha256(row: dict[str, Any] | pd.Series) -> str:
    payload = {
        "case_name": row.get("case_name", ""),
        "review_agreement_status": row.get("review_agreement_status", ""),
        "reviewer_a_identity": row.get("reviewer_a_identity", ""),
        "reviewer_a_owner": row.get("reviewer_a_owner", ""),
        "reviewer_a_started_at_utc": row.get("reviewer_a_started_at_utc", ""),
        "reviewer_a_completed_at_utc": row.get("reviewer_a_completed_at_utc", ""),
        "reviewer_a_packet_sha256": row.get("reviewer_a_packet_sha256", ""),
        "reviewer_a_decision_sha256": row.get("reviewer_a_decision_sha256", ""),
        "reviewer_b_identity": row.get("reviewer_b_identity", ""),
        "reviewer_b_owner": row.get("reviewer_b_owner", ""),
        "reviewer_b_started_at_utc": row.get("reviewer_b_started_at_utc", ""),
        "reviewer_b_completed_at_utc": row.get("reviewer_b_completed_at_utc", ""),
        "reviewer_b_packet_sha256": row.get("reviewer_b_packet_sha256", ""),
        "reviewer_b_decision_sha256": row.get("reviewer_b_decision_sha256", ""),
        "third_adjudicator_identity": row.get("third_adjudicator_identity", ""),
        "third_adjudicator_owner": row.get("third_adjudicator_owner", ""),
        "third_adjudicator_started_at_utc": row.get("third_adjudicator_started_at_utc", ""),
        "third_adjudicator_completed_at_utc": row.get("third_adjudicator_completed_at_utc", ""),
        "third_adjudicator_packet_sha256": row.get("third_adjudicator_packet_sha256", ""),
        "third_adjudicator_decision_sha256": row.get("third_adjudicator_decision_sha256", ""),
        "final_decision_sha256": row.get("final_decision_sha256", ""),
        "final_decision_completed_at_utc": row.get("final_decision_completed_at_utc", ""),
    }
    return _sha256_json(payload)


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def valid_utc_review_interval(start_value: object, end_value: object) -> bool:
    try:
        start = datetime.fromisoformat(str(start_value).strip().replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(end_value).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    return (
        start.tzinfo is not None
        and end.tzinfo is not None
        and start.utcoffset() == timezone.utc.utcoffset(start)
        and end.utcoffset() == timezone.utc.utcoffset(end)
        and end > start
    )


def utc_at_or_after(value: object, *prior_values: object) -> bool:
    try:
        current = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        priors = [datetime.fromisoformat(str(item).strip().replace("Z", "+00:00")) for item in prior_values]
    except (TypeError, ValueError):
        return False
    timestamps = [current, *priors]
    if any(item.tzinfo is None or item.utcoffset() != timezone.utc.utcoffset(item) for item in timestamps):
        return False
    return all(current >= item for item in priors)


def _as_frame(value: object) -> pd.DataFrame:
    if isinstance(value, pd.DataFrame):
        return value.copy()
    if value is None:
        return pd.DataFrame()
    if isinstance(value, list):
        return pd.DataFrame(value)
    raise TypeError(f"unsupported evidence frame type: {type(value)!r}")


def overlay_historical_snapshot_projection(
    positive_cases: pd.DataFrame,
    projection_rows: pd.DataFrame,
) -> pd.DataFrame:
    positive = positive_cases.copy()
    projection = projection_rows.copy()
    if positive.empty:
        return positive

    missing_positive = [column for column in _HISTORICAL_SNAPSHOT_IDENTIFIER_FIELDS if column not in positive.columns]
    if missing_positive:
        raise ValueError(f"historical_snapshot_positive_cases_missing_columns:{','.join(missing_positive)}")

    required_projection = [*_HISTORICAL_SNAPSHOT_IDENTIFIER_FIELDS, *HISTORICAL_SNAPSHOT_OVERLAY_FIELDS]
    missing_projection = [column for column in required_projection if column not in projection.columns]
    if missing_projection:
        raise ValueError(f"historical_snapshot_projection_missing_columns:{','.join(missing_projection)}")
    unexpected_projection = sorted(set(projection.columns) - set(required_projection))
    if unexpected_projection:
        raise ValueError(f"historical_snapshot_projection_unexpected_columns:{','.join(unexpected_projection)}")

    positive["case_id"] = positive["case_id"].astype(str)
    positive["case_name"] = positive["case_name"].astype(str)
    projection["case_id"] = projection["case_id"].astype(str)
    projection["case_name"] = projection["case_name"].astype(str)

    if positive["case_id"].duplicated().any():
        raise ValueError("historical_snapshot_positive_cases_duplicate_case_id")
    if projection["case_id"].duplicated().any():
        raise ValueError("historical_snapshot_projection_duplicate_case_id")

    expected_ids = set(positive["case_id"].tolist())
    observed_ids = set(projection["case_id"].tolist())
    missing_ids = sorted(expected_ids - observed_ids)
    unexpected_ids = sorted(observed_ids - expected_ids)
    if missing_ids:
        raise ValueError("historical_snapshot_projection_missing_case_id")
    if unexpected_ids:
        raise ValueError("historical_snapshot_projection_unexpected_case_id")

    case_name_by_id = positive.set_index("case_id")["case_name"].to_dict()
    if any(projection_case_name != case_name_by_id.get(case_id, "") for case_id, projection_case_name in projection[["case_id", "case_name"]].itertuples(index=False, name=None)):
        raise ValueError("historical_snapshot_projection_case_name_mismatch")

    projection = projection.set_index("case_id")
    for field in HISTORICAL_SNAPSHOT_OVERLAY_FIELDS:
        positive[field] = positive["case_id"].map(projection[field])
    return positive


def _counter(required: int, observed: int, passed: bool, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "required": int(required),
        "observed": int(observed),
        "passed": bool(passed),
    }
    if details:
        payload["details"] = details
    return payload


def _resolve_counter_targets(value: object) -> dict[str, Any]:
    if value is None:
        return {
            "deployment_denominator_required": DEFAULT_COUNTER_TARGETS["deployment_denominator_required"],
            "deployment_denominator_per_chain": dict(DEFAULT_COUNTER_TARGETS["deployment_denominator_per_chain"]),
            "control_candidates_required": DEFAULT_COUNTER_TARGETS["control_candidates_required"],
            "qualified_controls_required": DEFAULT_COUNTER_TARGETS["qualified_controls_required"],
            "independent_r5_blocks_required": DEFAULT_COUNTER_TARGETS["independent_r5_blocks_required"],
        }
    if not isinstance(value, dict):
        raise ValueError("counter_targets must be a mapping")
    missing = sorted(set(COUNTER_TARGET_KEYS) - set(value.keys()))
    unexpected = sorted(set(value.keys()) - set(COUNTER_TARGET_KEYS))
    if missing or unexpected:
        raise ValueError(
            f"counter_targets keys invalid: missing={missing or '[]'} unexpected={unexpected or '[]'}"
        )
    per_chain = value.get("deployment_denominator_per_chain")
    if not isinstance(per_chain, dict):
        raise ValueError("deployment_denominator_per_chain must be a mapping")
    expected_chains = set(DEFAULT_COUNTER_TARGETS["deployment_denominator_per_chain"].keys())
    missing_chains = sorted(expected_chains - set(per_chain.keys()))
    unexpected_chains = sorted(set(per_chain.keys()) - expected_chains)
    if missing_chains or unexpected_chains:
        raise ValueError(
            "deployment_denominator_per_chain invalid: "
            f"missing={missing_chains or '[]'} unexpected={unexpected_chains or '[]'}"
        )
    normalized = {
        "deployment_denominator_required": int(value["deployment_denominator_required"]),
        "deployment_denominator_per_chain": {
            chain: int(per_chain[chain])
            for chain in sorted(expected_chains)
        },
        "control_candidates_required": int(value["control_candidates_required"]),
        "qualified_controls_required": int(value["qualified_controls_required"]),
        "independent_r5_blocks_required": int(value["independent_r5_blocks_required"]),
    }
    for key in (
        "deployment_denominator_required",
        "control_candidates_required",
        "qualified_controls_required",
        "independent_r5_blocks_required",
    ):
        if normalized[key] < 0:
            raise ValueError(f"{key} must be non-negative")
    if any(count < 0 for count in normalized["deployment_denominator_per_chain"].values()):
        raise ValueError("deployment_denominator_per_chain values must be non-negative")
    return normalized


def build_review_bundle(
    source_rows: pd.DataFrame,
    *,
    packet_type: str,
    blinding_seed: str,
) -> list[dict[str, Any]]:
    visible_fields = [field for field in _REVIEW_VISIBLE_FIELDS if field in source_rows.columns]
    if "case_name" not in visible_fields:
        raise ValueError("source_rows must include case_name")

    packets: list[dict[str, Any]] = []
    blinding_seed_sha256 = hashlib.sha256(blinding_seed.encode("utf-8")).hexdigest()
    for index, record in enumerate(source_rows.to_dict("records"), start=1):
        visible_payload = {field: record.get(field) for field in visible_fields}
        packet_material = {
            "packet_type": packet_type,
            "source_manifest_sha256": record.get("source_manifest_sha256", ""),
            "visible_payload": visible_payload,
            "blinding_seed_sha256": blinding_seed_sha256,
        }
        packet_sha = _sha256_json(packet_material)
        packets.append(
            {
                "packet_id": f"{packet_type}-{index:04d}",
                "packet_type": packet_type,
                "source_manifest_sha256": record.get("source_manifest_sha256", ""),
                "visible_fields": visible_fields,
                "visible_payload": visible_payload,
                "blinding_seed_sha256": blinding_seed_sha256,
                "assignment_placeholder": "",
                "packet_sha256": packet_sha,
            }
        )
    return packets


def _strict_historical_snapshot_counter(positive_cases: pd.DataFrame) -> dict[str, Any]:
    required = len(positive_cases)
    if positive_cases.empty:
        return _counter(0, 0, False)

    required_columns = [
        "historical_snapshot_status",
        "historical_snapshot_source_receipt_sha256",
        "historical_snapshot_identity_receipt_sha256",
        "historical_snapshot_source_provider_family",
        "historical_snapshot_identity_provider_family",
        "historical_snapshot_schema_valid",
        "historical_snapshot_hash_bound",
    ]
    missing = [column for column in required_columns if column not in positive_cases.columns]
    if missing:
        return _counter(required, 0, False, details={"missing_columns": missing})

    strict_rows = positive_cases.apply(
        lambda row: (
            str(row["historical_snapshot_status"]) == STRICT_HISTORICAL_STATUS
            and _is_sha256(row["historical_snapshot_source_receipt_sha256"])
            and _is_sha256(row["historical_snapshot_identity_receipt_sha256"])
            and bool(row["historical_snapshot_schema_valid"])
            and bool(row["historical_snapshot_hash_bound"])
            and str(row["historical_snapshot_source_provider_family"]).strip()
            and str(row["historical_snapshot_identity_provider_family"]).strip()
            and str(row["historical_snapshot_source_provider_family"]).strip()
            != str(row["historical_snapshot_identity_provider_family"]).strip()
        ),
        axis=1,
    )
    observed = int(strict_rows.sum())
    return _counter(required, observed, observed >= required)


def _strict_independent_adjudications_counter(
    positive_cases: pd.DataFrame,
    positive_packets: list[dict[str, Any]],
) -> dict[str, Any]:
    if positive_cases.empty:
        return _counter(0, 0, False)

    required_columns = [
        "review_decision_status",
        "decision_schema_valid",
        "decision_hash_bound",
        "reviewer_a_identity",
        "reviewer_a_owner",
        "reviewer_a_conflict_clear",
        "reviewer_a_confidence",
        "reviewer_a_started_at_utc",
        "reviewer_a_completed_at_utc",
        "reviewer_a_packet_sha256",
        "reviewer_a_decision_sha256",
        "reviewer_b_identity",
        "reviewer_b_owner",
        "reviewer_b_conflict_clear",
        "reviewer_b_confidence",
        "reviewer_b_started_at_utc",
        "reviewer_b_completed_at_utc",
        "reviewer_b_packet_sha256",
        "reviewer_b_decision_sha256",
        "review_agreement_status",
        "final_decision_sha256",
        "final_decision_completed_at_utc",
        "final_decision_input_binding_sha256",
        "decision_case_schema_valid",
        "decision_case_hash_bound",
        "decision_case_stale",
        "third_adjudicator_identity",
        "third_adjudicator_owner",
        "third_adjudicator_conflict_clear",
        "third_adjudicator_confidence",
        "third_adjudicator_started_at_utc",
        "third_adjudicator_completed_at_utc",
        "third_adjudicator_packet_sha256",
        "third_adjudicator_decision_sha256",
    ]
    missing = [column for column in required_columns if column not in positive_cases.columns]
    if missing:
        return _counter(len(positive_cases), 0, False, details={"missing_columns": missing})

    packet_hashes_by_case = {
        str(packet.get("visible_payload", {}).get("case_name", "")).strip(): str(packet.get("packet_sha256", "")).strip().lower()
        for packet in positive_packets
        if isinstance(packet, dict) and isinstance(packet.get("visible_payload"), dict)
    }
    if len(packet_hashes_by_case) != len(positive_cases) or set(packet_hashes_by_case) != set(positive_cases["case_name"].astype(str)):
        return _counter(
            len(positive_cases),
            0,
            False,
            details={"reason": "positive_review_packet_case_binding_incomplete"},
        )

    qualifying_rows = positive_cases.apply(
        lambda row: (
            str(row["review_decision_status"]) == "FINALIZED_INDEPENDENT_ADJUDICATION"
            and bool(row["decision_schema_valid"])
            and bool(row["decision_hash_bound"])
            and bool(row["decision_case_schema_valid"])
            and bool(row["decision_case_hash_bound"])
            and not bool(row["decision_case_stale"])
            and str(row["reviewer_a_identity"]).strip() not in {"", "AI", "PUBLIC", "PUBLIC_LABEL", "SAME_OWNER"}
            and str(row["reviewer_b_identity"]).strip() not in {"", "AI", "PUBLIC", "PUBLIC_LABEL", "SAME_OWNER"}
            and str(row["reviewer_a_identity"]).strip() != str(row["reviewer_b_identity"]).strip()
            and str(row["reviewer_a_owner"]).strip() not in {"", "SAME_OWNER"}
            and str(row["reviewer_b_owner"]).strip() not in {"", "SAME_OWNER"}
            and str(row["reviewer_a_owner"]).strip() != str(row["reviewer_b_owner"]).strip()
            and bool(row["reviewer_a_conflict_clear"])
            and bool(row["reviewer_b_conflict_clear"])
            and str(row["reviewer_a_confidence"]).strip().lower() in STRICT_HUMAN_CONFIDENCE
            and str(row["reviewer_b_confidence"]).strip().lower() in STRICT_HUMAN_CONFIDENCE
            and valid_utc_review_interval(row["reviewer_a_started_at_utc"], row["reviewer_a_completed_at_utc"])
            and valid_utc_review_interval(row["reviewer_b_started_at_utc"], row["reviewer_b_completed_at_utc"])
            and _is_sha256(row["reviewer_a_packet_sha256"])
            and _is_sha256(row["reviewer_b_packet_sha256"])
            and str(row["reviewer_a_packet_sha256"]).strip().lower()
            == packet_hashes_by_case.get(str(row["case_name"]), "")
            and str(row["reviewer_b_packet_sha256"]).strip().lower()
            == packet_hashes_by_case.get(str(row["case_name"]), "")
            and _is_sha256(row["reviewer_a_decision_sha256"])
            and _is_sha256(row["reviewer_b_decision_sha256"])
            and (
                (
                    str(row["review_agreement_status"]).strip() == "REVIEWER_CONSENSUS"
                    and str(row["third_adjudicator_identity"]).strip() == ""
                    and str(row["third_adjudicator_owner"]).strip() == ""
                    and str(row["third_adjudicator_started_at_utc"]).strip() == ""
                    and str(row["third_adjudicator_completed_at_utc"]).strip() == ""
                    and not _is_sha256(row["third_adjudicator_packet_sha256"])
                    and not _is_sha256(row["third_adjudicator_decision_sha256"])
                )
                or (
                    str(row["review_agreement_status"]).strip() == "THIRD_ADJUDICATOR_COMPLETE"
                    and str(row["third_adjudicator_identity"]).strip() not in {"", "AI", "PUBLIC", "PUBLIC_LABEL", "SAME_OWNER"}
                    and str(row["third_adjudicator_owner"]).strip() not in {"", "SAME_OWNER"}
                    and str(row["third_adjudicator_owner"]).strip()
                    not in {str(row["reviewer_a_owner"]).strip(), str(row["reviewer_b_owner"]).strip()}
                    and bool(row["third_adjudicator_conflict_clear"])
                    and str(row["third_adjudicator_confidence"]).strip().lower() in STRICT_HUMAN_CONFIDENCE
                    and valid_utc_review_interval(
                        row["third_adjudicator_started_at_utc"], row["third_adjudicator_completed_at_utc"]
                    )
                    and _is_sha256(row["third_adjudicator_packet_sha256"])
                    and _is_sha256(row["third_adjudicator_decision_sha256"])
                    and utc_at_or_after(
                        row["final_decision_completed_at_utc"], row["third_adjudicator_completed_at_utc"]
                    )
                )
            )
            and _is_sha256(row["final_decision_sha256"])
            and utc_at_or_after(
                row["final_decision_completed_at_utc"],
                row["reviewer_a_completed_at_utc"],
                row["reviewer_b_completed_at_utc"],
            )
            and str(row["final_decision_input_binding_sha256"]).strip().lower()
            == make_independent_adjudication_binding_sha256(row).lower()
        ),
        axis=1,
    )
    observed = int(qualifying_rows.sum())
    return _counter(len(positive_cases), observed, observed >= len(positive_cases))


def _deployment_denominator_counter(
    denominator: pd.DataFrame,
    *,
    required_total: int,
    required_per_chain: dict[str, int],
) -> dict[str, Any]:
    if denominator.empty:
        return _counter(required_total, 0, False)
    qualifying_rows = denominator.apply(
        lambda row: str(row.get("admissibility_status", "")) == "VERIFIED"
        and _is_sha256(row.get("selection_rank_sha256", "")),
        axis=1,
    )
    observed = int(qualifying_rows.sum())
    if "chain" not in denominator.columns:
        return _counter(required_total, observed, False, details={"missing_columns": ["chain"]})
    qualifying = denominator.loc[qualifying_rows].copy()
    per_chain_counts = {
        chain: int(
            qualifying["chain"].astype(str).str.strip().str.lower().eq(chain).sum()
        )
        for chain in sorted(required_per_chain.keys())
    }
    passed = all(per_chain_counts[chain] >= required_per_chain[chain] for chain in required_per_chain)
    return _counter(
        required_total,
        observed,
        passed,
        details={
            "per_chain_observed": per_chain_counts,
            "per_chain_required": {chain: int(required_per_chain[chain]) for chain in sorted(required_per_chain)},
        },
    )


def _control_counters(
    control_rows: pd.DataFrame,
    *,
    candidate_required: int,
    qualified_required: int,
    positive_case_names: list[str],
    qualification_verification: object = None,
    selection_verification: object = None,
    controls_per_positive: int = 10,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if control_rows.empty:
        return _counter(candidate_required, 0, False), _counter(qualified_required, 0, False)
    try:
        revalidated = qualify_control_rows(control_rows)
    except ValueError as exc:
        return (
            _counter(candidate_required, 0, False, details={"validation_error": str(exc)}),
            _counter(qualified_required, 0, False, details={"validation_error": str(exc)}),
        )
    candidate_rows_observed = int(
        revalidated.get("candidate_row_valid", pd.Series(dtype=bool)).map(bool).sum()
    )
    scientifically_qualified = int(
        revalidated.get("qualified_control", pd.Series(dtype=bool)).map(bool).sum()
    )
    candidate_structure = verify_control_cohort_structure(
        revalidated,
        valid_column="candidate_row_valid",
        expected_case_names=positive_case_names,
        controls_per_positive=controls_per_positive,
    )
    selection_blocker: str | None = None
    if not isinstance(selection_verification, dict):
        selection_blocker = "missing_control_selection_verification"
    else:
        frozen_hashes = (
            revalidated.sort_values(
                ["case_name", "control_rank", "chain", "contract_address"],
                kind="stable",
            ).get("frozen_candidate_sha256", pd.Series(dtype=str)).astype(str).tolist()
        )
        required_selection = {
            "decision": "FROZEN_CONTROL_COHORT_VERIFIED_NON_AUTHORIZING",
            "complete": True,
            "status": "FROZEN_COMPLETE",
            "target_control_rows": candidate_required,
            "frozen_candidate_hashes_sha256": _sha256_json(frozen_hashes),
            "counter_authority": False,
        }
        if (
            not bool(candidate_structure.get("passed"))
            or candidate_rows_observed != candidate_required
            or any(
                selection_verification.get(field) != expected
                for field, expected in required_selection.items()
            )
            or len(frozen_hashes) != candidate_required
            or not all(_is_sha256(value) for value in frozen_hashes)
        ):
            selection_blocker = "control_selection_verification_mismatch"
    candidates = 0 if selection_blocker else candidate_rows_observed
    authority_blocker: str | None = selection_blocker
    if scientifically_qualified:
        if not isinstance(qualification_verification, dict):
            authority_blocker = "missing_control_qualification_verification"
        else:
            expected_records = json.loads(
                revalidated.sort_values(
                    ["case_name", "control_rank", "chain", "contract_address"],
                    kind="stable",
                ).to_json(orient="records", date_format="iso")
            )
            expected_binding = _sha256_json(expected_records)
            expected_schema_decisions = {
                (
                    "chronosaudit.control_qualification_approval_verification.v1",
                    "CONTROL_QUALIFICATION_APPROVAL_VERIFIED",
                ),
                (
                    "chronosaudit.control_qualification_bundle_verification.v1",
                    "CONTROL_QUALIFICATION_BUNDLE_VERIFIED",
                ),
            }
            required_values = {
                "candidate_rows": int(len(revalidated)),
                "qualified_rows": scientifically_qualified,
                "qualified_records_sha256": expected_binding,
                "qualification_projection_authorized": True,
                "counter_authority": True,
                "selection_authorized": False,
                "stage_promotion_authorized": False,
                "recovery3_mutation_authorized": False,
                "authority_type": "ACCOUNTABLE_HUMAN",
                "authority_identity_binding_verified": True,
            }
            if (
                (
                    qualification_verification.get("schema_version"),
                    qualification_verification.get("decision"),
                )
                not in expected_schema_decisions
                or any(
                qualification_verification.get(field) != expected
                for field, expected in required_values.items()
                )
            ):
                authority_blocker = "control_qualification_verification_mismatch"
            else:
                if not _is_sha256(
                    qualification_verification.get(
                        "authority_identity_binding_sha256", ""
                    )
                ):
                    authority_blocker = (
                        "control_qualification_human_authority_unestablished"
                    )
                binding_fields = {
                    "qualification_request_sha256": "request_sha256",
                    "qualification_approval_sha256": "approval_sha256",
                    "qualification_signature_sha256": "signature_sha256",
                    "qualification_allowed_signers_sha256": "allowed_signers_sha256",
                    "qualification_evidence_batch_sha256": "verified_check_records_sha256",
                }
                principal = str(
                    qualification_verification.get("authority_principal") or ""
                ).strip()
                qualified_rows = revalidated.loc[
                    revalidated["qualified_control"].map(bool)
                ]
                if authority_blocker is None and (
                    not principal
                    or any(
                        not _is_sha256(qualification_verification.get(report_field, ""))
                        for report_field in binding_fields.values()
                    )
                    or "qualification_authority_verified" not in qualified_rows.columns
                    or not qualified_rows["qualification_authority_verified"].map(bool).all()
                    or "selected_candidate_control_row_sha256" not in qualified_rows.columns
                    or not qualified_rows["selected_candidate_control_row_sha256"].map(_is_sha256).all()
                    or "qualification_authority_principal" not in qualified_rows.columns
                    or not qualified_rows["qualification_authority_principal"].astype(str).eq(principal).all()
                    or any(
                        row_field not in qualified_rows.columns
                        or not qualified_rows[row_field].astype(str).eq(
                            str(qualification_verification[report_field])
                        ).all()
                        for row_field, report_field in binding_fields.items()
                    )
                ):
                    authority_blocker = "control_qualification_projection_binding_invalid"
    qualified = 0 if authority_blocker else scientifically_qualified
    qualified_structure = verify_control_cohort_structure(
        revalidated,
        valid_column="qualified_control",
        expected_case_names=positive_case_names,
        controls_per_positive=controls_per_positive,
    )
    candidate_details = (
        {key: value for key, value in candidate_structure.items() if key != "passed"}
        if candidates == candidate_required
        else None
    )
    qualified_details = (
        {key: value for key, value in qualified_structure.items() if key != "passed"}
        if qualified == qualified_required
        else None
    )
    if selection_blocker:
        candidate_details = {
            "mechanically_valid_rows": candidate_rows_observed,
            "selection_blocker": selection_blocker,
        }
    if authority_blocker:
        qualified_details = {
            "scientifically_qualified_rows": scientifically_qualified,
            "authority_blocker": authority_blocker,
        }
    return (
        _counter(
            candidate_required,
            candidates,
            candidates == candidate_required and bool(candidate_structure["passed"]),
            details=candidate_details,
        ),
        _counter(
            qualified_required,
            qualified,
            qualified == qualified_required and bool(qualified_structure["passed"]),
            details=qualified_details,
        ),
    )


def _independent_r5_counter(
    positive_cases: pd.DataFrame,
    minimum_independent_r5_blocks: int,
) -> dict[str, Any]:
    if positive_cases.empty:
        return _counter(minimum_independent_r5_blocks, 0, False)

    required_columns = [
        "mechanism_component_status",
        "lineage_component_status",
        "clone_leakage_free",
        "proxy_leakage_free",
        "protocol_leakage_free",
        "mechanism_leakage_free",
        "r5_component_hash_bound",
        "r5_component_schema_valid",
    ]
    missing = [column for column in required_columns if column not in positive_cases.columns]
    if missing:
        return _counter(minimum_independent_r5_blocks, 0, False, details={"missing_columns": missing})

    observed = int(
        positive_cases.apply(
            lambda row: (
                str(row["mechanism_component_status"]) == "FINALIZED_COMPONENT"
                and str(row["lineage_component_status"]) == "FINALIZED_COMPONENT"
                and bool(row["clone_leakage_free"])
                and bool(row["proxy_leakage_free"])
                and bool(row["protocol_leakage_free"])
                and bool(row["mechanism_leakage_free"])
                and bool(row["r5_component_hash_bound"])
                and bool(row["r5_component_schema_valid"])
            ),
            axis=1,
        ).sum()
    )
    return _counter(minimum_independent_r5_blocks, observed, observed >= minimum_independent_r5_blocks)


def _case_release_inputs(
    positive_cases: pd.DataFrame,
    counters: dict[str, dict[str, Any]],
) -> pd.DataFrame:
    if positive_cases.empty:
        return pd.DataFrame(columns=["case_name"])
    case_rows = pd.DataFrame({"case_name": positive_cases["case_name"].astype(str)})
    case_rows["historical_snapshots_ready"] = counters["historical_snapshots"]["passed"]
    case_rows["independent_adjudications_ready"] = counters["independent_adjudications"]["passed"]
    case_rows["deployment_denominator_ready"] = counters["deployment_denominator"]["passed"]
    case_rows["control_candidates_ready"] = counters["control_candidates"]["passed"]
    case_rows["qualified_controls_ready"] = counters["qualified_controls"]["passed"]
    case_rows["independent_r5_blocks_ready"] = counters["independent_r5_blocks"]["passed"]
    case_rows["case_hash_bound"] = positive_cases.get("decision_case_hash_bound", False).map(bool)
    case_rows["case_schema_valid"] = positive_cases.get("decision_case_schema_valid", False).map(bool)
    case_rows["case_not_stale"] = ~positive_cases.get("decision_case_stale", True).map(bool)
    case_rows["policy_thresholds_met"] = positive_cases.apply(
        lambda row: (
            bool(row.get("clone_leakage_free", False))
            and bool(row.get("proxy_leakage_free", False))
            and bool(row.get("protocol_leakage_free", False))
            and bool(row.get("mechanism_leakage_free", False))
        ),
        axis=1,
    )
    return case_rows


def project_counters(evidence: dict[str, object]) -> dict[str, Any]:
    counter_targets = _resolve_counter_targets(evidence.get("counter_targets"))
    positive_cases = _as_frame(evidence.get("positive_cases"))
    denominator = _as_frame(evidence.get("deployment_denominator"))
    control_rows = _as_frame(evidence.get("control_rows"))
    positive_packets = list(evidence.get("positive_case_review_packets") or [])
    control_packets = list(evidence.get("control_review_packets") or [])
    finalized_positive_adjudications = list(evidence.get("finalized_positive_adjudications") or [])
    if finalized_positive_adjudications:
        finalized_frame = pd.DataFrame(finalized_positive_adjudications)
        if "case_name" not in finalized_frame.columns:
            raise ValueError("finalized_positive_adjudications must include case_name")
        if finalized_frame["case_name"].astype(str).duplicated().any():
            raise ValueError("finalized_positive_adjudications contains duplicate case_name")
        unexpected_cases = sorted(
            set(finalized_frame["case_name"].astype(str)) - set(positive_cases["case_name"].astype(str))
        )
        if unexpected_cases:
            raise ValueError(f"finalized_positive_adjudications contains unexpected cases: {unexpected_cases}")
        review_columns = [column for column in finalized_frame.columns if column != "case_name"]
        positive_cases = positive_cases.drop(columns=review_columns, errors="ignore").merge(
            finalized_frame[["case_name", *review_columns]],
            on="case_name",
            how="left",
            validate="one_to_one",
        )
    minimum_independent_r5_blocks = int(
        evidence.get("minimum_independent_r5_blocks", counter_targets["independent_r5_blocks_required"])
    )
    if minimum_independent_r5_blocks != int(counter_targets["independent_r5_blocks_required"]):
        raise ValueError("minimum_independent_r5_blocks must match counter_targets.independent_r5_blocks_required")

    counters = {
        "historical_snapshots": _strict_historical_snapshot_counter(positive_cases),
        "independent_adjudications": _strict_independent_adjudications_counter(positive_cases, positive_packets),
        "deployment_denominator": _deployment_denominator_counter(
            denominator,
            required_total=int(counter_targets["deployment_denominator_required"]),
            required_per_chain=counter_targets["deployment_denominator_per_chain"],
        ),
    }
    positive_case_names = positive_cases["case_name"].astype(str).tolist()
    required_control_candidates = int(counter_targets["control_candidates_required"])
    controls_per_positive = (
        required_control_candidates // len(positive_case_names)
        if positive_case_names
        and required_control_candidates % len(positive_case_names) == 0
        else 10
    )
    control_candidates, qualified_controls = _control_counters(
        control_rows,
        candidate_required=required_control_candidates,
        qualified_required=int(counter_targets["qualified_controls_required"]),
        positive_case_names=positive_case_names,
        qualification_verification=evidence.get("control_qualification_verification"),
        selection_verification=evidence.get("control_selection_verification"),
        controls_per_positive=controls_per_positive,
    )
    counters["control_candidates"] = control_candidates
    counters["qualified_controls"] = qualified_controls
    counters["independent_r5_blocks"] = _independent_r5_counter(
        positive_cases,
        minimum_independent_r5_blocks,
    )
    counters["positive_case_review_packets"] = _counter(0, len(positive_packets), True)
    counters["control_review_packets"] = _counter(0, len(control_packets), True)
    counters["finalized_positive_adjudications"] = _counter(0, len(finalized_positive_adjudications), True)

    release_inputs = _case_release_inputs(positive_cases, counters)
    release_projection = verify_release_eligibility(release_inputs) if not release_inputs.empty else {
        "release_eligible_cases": 0,
        "eligible_case_names": [],
        "release_gate_columns": [],
    }
    qualified = all(counters[key]["passed"] for key in CORE_COUNTER_KEYS if key != "release_eligible_cases")
    qualified = qualified and release_projection["release_eligible_cases"] > 0

    return {
        **counters,
        "release_eligible_cases": int(release_projection["release_eligible_cases"]),
        "eligible_case_names": release_projection["eligible_case_names"],
        "production_qualification": {
            "qualified": qualified,
            "core_counter_keys": list(CORE_COUNTER_KEYS),
            "packet_counter_keys": list(PACKET_COUNTER_KEYS),
        },
    }


def build_counter_artifact(
    evidence: dict[str, object],
    *,
    input_manifest_sha256: str,
) -> dict[str, Any]:
    if not _is_sha256(input_manifest_sha256):
        raise ValueError("input_manifest_sha256 must be a 64-character sha256 hex digest")
    projected = project_counters(evidence)
    counters = {key: projected[key] for key in (*CORE_COUNTER_KEYS[:-1], "release_eligible_cases", *PACKET_COUNTER_KEYS)}
    return {
        "artifact_schema_version": COUNTER_ARTIFACT_VERSION,
        "input_manifest_sha256": input_manifest_sha256,
        "counters": counters,
    }


def validate_counter_artifact(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    unexpected_top_level = sorted(set(payload.keys()) - COUNTER_ARTIFACT_ALLOWED_KEYS)
    if unexpected_top_level:
        errors.append(f"unexpected_top_level_keys:{','.join(unexpected_top_level)}")
    if payload.get("artifact_schema_version") != COUNTER_ARTIFACT_VERSION:
        errors.append("invalid_artifact_schema_version")
    if not _is_sha256(payload.get("input_manifest_sha256", "")):
        errors.append("invalid_input_manifest_sha256")
    counters = payload.get("counters")
    if not isinstance(counters, dict):
        errors.append("missing_counters")
        return errors
    unexpected_counter_keys = sorted(set(counters.keys()) - COUNTER_ALLOWED_KEYS)
    if unexpected_counter_keys:
        errors.append(f"unexpected_counter_keys:{','.join(unexpected_counter_keys)}")
    for key in (*CORE_COUNTER_KEYS[:-1], *PACKET_COUNTER_KEYS):
        if key not in counters:
            errors.append(f"missing_counter:{key}")
    if "release_eligible_cases" not in counters:
        errors.append("missing_counter:release_eligible_cases")
    for key in (*CORE_COUNTER_KEYS[:-1], *PACKET_COUNTER_KEYS):
        counter = counters.get(key)
        if not isinstance(counter, dict):
            errors.append(f"invalid_counter_shape:{key}")
            continue
        if set(counter.keys()) != {"required", "observed", "passed"} and set(counter.keys()) != {"required", "observed", "passed", "details"}:
            errors.append(f"invalid_counter_fields:{key}")
        if not isinstance(counter.get("required"), int) or counter["required"] < 0:
            errors.append(f"invalid_counter_required:{key}")
        if not isinstance(counter.get("observed"), int) or counter["observed"] < 0:
            errors.append(f"invalid_counter_observed:{key}")
        if not isinstance(counter.get("passed"), bool):
            errors.append(f"invalid_counter_passed:{key}")
    if not isinstance(counters.get("release_eligible_cases"), int) or counters["release_eligible_cases"] < 0:
        errors.append("invalid_release_eligible_cases")
    return errors


def write_counter_artifact(
    path: str | Path,
    evidence: dict[str, object],
    *,
    input_manifest_sha256: str,
) -> dict[str, Any]:
    payload = build_counter_artifact(evidence, input_manifest_sha256=input_manifest_sha256)
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload
