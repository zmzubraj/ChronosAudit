from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.counters import (  # noqa: E402
    build_counter_artifact,
    build_review_bundle,
    canonical_manifest_sha256,
    make_independent_adjudication_binding_sha256,
    overlay_historical_snapshot_projection,
    project_counters,
    qualify_control_rows,
    utc_at_or_after,
    valid_utc_review_interval,
    validate_counter_artifact,
)
from chronosaudit_stage2.ai_adjudication import (  # noqa: E402
    AI_TRACK_NAME,
    HUMAN_COUNTER_EFFECT,
    evaluate_ai_adjudications,
)
from chronosaudit_stage2.public_acquisition.ledger import AppendOnlyLedger  # noqa: E402
from chronosaudit_stage2.public_acquisition.qualification import STRICT_HUMAN_CONFIDENCE  # noqa: E402
from chronosaudit_stage2.public_acquisition.queue import build_case_queue  # noqa: E402
from production_qualification import (  # noqa: E402
    load_verified_control_qualification_bundle,
    load_verified_historical_projection,
    validate_counter_input_manifest,
)

from run_public_evidence_acquisition import (  # noqa: E402
    DEFAULT_REVISION,
    RPC_REQUIRED_CELLS,
    _canonical_json,
    _canonical_request_bytes,
    _discover_latest_run,
    _iter_provider_observations,
    _json_dumps,
    _load_policy,
    _projectable_positive_cases,
    _read_json,
    _run_paths,
)

REVIEW_VISIBLE_FIELDS = [
    "case_name",
    "incident_name",
    "chain",
    "target_contract_address",
    "incident_date",
]
RPC_ACCEPTED_STATUSES = {
    "NOT_ATTEMPTED",
    "PARTIAL",
    "VERIFIED",
    "DISPUTED",
    "UNAVAILABLE",
    "POLICY_EXCLUDED",
    "WAITING_EXTERNAL",
}
PILOT_A2_RUN_ID = "evidence-grade-pilot-amendment-a2"
PILOT_A2_REVISION = "2026-08-09"


def _integrity_error(result: dict[str, Any], message: str) -> None:
    result["integrity_failures"].append(message)
    result["structure_valid"] = False


def _record_check(result: dict[str, Any], *, name: str, required: Any, observed: Any, passed: bool) -> None:
    result["checks"].append({"name": name, "required": required, "observed": observed, "passed": bool(passed)})


def _write_markdown_report(report_path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# Public Acquisition Verification",
        "",
        f"- Run ID: `{payload['run_id']}`",
        f"- Revision: `{payload['revision']}`",
        f"- Structure valid: `{payload['structure_valid']}`",
        f"- Scientifically complete: `{payload['scientifically_complete']}`",
        f"- Release ready: `{payload['release_ready']}`",
        "",
        "## Checks",
    ]
    for check in payload["checks"]:
        lines.append(f"- `{check['name']}`: {'PASS' if check['passed'] else 'FAIL'}")
        lines.append(f"  required={check['required']}")
        lines.append(f"  observed={check['observed']}")
    lines.append("")
    lines.append("## Integrity Failures")
    if payload["integrity_failures"]:
        for item in payload["integrity_failures"]:
            lines.append(f"- {item}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Scientific Gaps")
    if payload["scientific_gaps"]:
        for item in payload["scientific_gaps"]:
            lines.append(f"- {item}")
    else:
        lines.append("- none")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _safe_read_csv(path: Path) -> pd.DataFrame:
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def _validate_denominator_identity(denominator: pd.DataFrame) -> None:
    if denominator.empty:
        return
    required_columns = {"deployment_id", "chain", "contract_address"}
    missing = sorted(required_columns - set(denominator.columns))
    if missing:
        raise ValueError(f"denominator missing required identity columns: {','.join(missing)}")
    for column in ("deployment_id", "chain", "contract_address"):
        series = denominator[column]
        if series.isna().any() or series.astype(str).str.strip().eq("").any():
            raise ValueError(f"denominator identity field contains blank values: {column}")
    if denominator["deployment_id"].duplicated().any():
        raise ValueError("duplicate deployment_id detected")
    if denominator.duplicated(subset=["chain", "contract_address"]).any():
        raise ValueError("duplicate chain-scoped deployment identity detected")


def _frame_equivalent(left: pd.DataFrame, right: pd.DataFrame) -> bool:
    if list(left.columns) != list(right.columns):
        return False
    left_norm = left.astype("object").where(pd.notna(left), "").astype(str)
    right_norm = right.astype("object").where(pd.notna(right), "").astype(str)
    return left_norm.equals(right_norm)


def _safe_run_path(paths, candidate: str) -> Path:
    path = Path(candidate)
    resolved = (paths.output_root / path).resolve(strict=False) if not path.is_absolute() else path.resolve(strict=False)
    run_root = paths.output_root.resolve()
    try:
        resolved.relative_to(run_root)
    except ValueError as exc:
        raise ValueError(f"path escapes output root containment: {candidate}") from exc
    try:
        resolved.relative_to(paths.raw_dir)
    except ValueError:
        try:
            resolved.relative_to(paths.processed_dir)
        except ValueError:
            try:
                resolved.relative_to(paths.report_dir)
            except ValueError as exc:
                raise ValueError(f"path outside run root: {candidate}") from exc
    if resolved.exists() and resolved.is_symlink():
        raise ValueError(f"symlinked artifact rejected: {candidate}")
    if not resolved.exists():
        raise FileNotFoundError(candidate)
    return resolved


def _evaluate_amendment_a2_pilot(output_root: Path) -> tuple[dict[str, Any], bool]:
    report_dir = output_root / "reports" / "public_acquisition" / PILOT_A2_REVISION / PILOT_A2_RUN_ID
    processed_dir = output_root / "processed" / "public_acquisition" / PILOT_A2_REVISION / PILOT_A2_RUN_ID
    closure_path = report_dir / "pilot_closure_report.json"
    queue_path = processed_dir / "pilot_case_queue_amended.csv"
    observed: dict[str, Any] = {
        "amendment_id": PILOT_A2_RUN_ID,
        "present": False,
    }
    if not closure_path.exists() or not queue_path.exists():
        return observed, False

    closure = _read_json(closure_path)
    queue = _safe_read_csv(queue_path)
    chain_counts = {str(chain): int(count) for chain, count in queue.get("chain", pd.Series(dtype=str)).value_counts().sort_index().items()}
    observed.update(
        {
            "present": True,
            "disposition": closure.get("disposition"),
            "status": closure.get("status"),
            "pilot_case_count": int(closure.get("pilot_case_count") or 0),
            "cases_attempted": int(closure.get("cases_attempted") or 0),
            "strict_snapshots_closed": int(closure.get("strict_snapshots_closed") or 0),
            "queue_rows": int(len(queue)),
            "chain_counts": chain_counts,
            "release_eligible": bool(closure.get("release_eligible")),
        }
    )
    complete = (
        str(closure.get("disposition")) == "COMPLETE"
        and str(closure.get("status")) == "complete"
        and int(closure.get("pilot_case_count") or 0) == 10
        and int(closure.get("cases_attempted") or 0) == 10
        and int(closure.get("strict_snapshots_closed") or 0) == 10
        and len(queue) == 10
        and chain_counts == {"arbitrum": 3, "base": 1, "bsc": 3, "ethereum": 3}
    )
    return observed, complete


def _nested_observation_identity(case_id: str, observation: dict[str, Any]) -> tuple[str, str, str, str, str, str, str, int]:
    return (
        case_id,
        str(observation.get("provider_family", "")),
        str(observation.get("provider_id", "")),
        str(observation.get("method", "")),
        _canonical_json(list(observation.get("params", []))),
        str(observation.get("request_sha256", "")),
        "" if observation.get("response_sha256") in (None, "") else str(observation.get("response_sha256", "")),
        int(observation.get("attempt", 0) or 0),
    )


def _receipt_identity(receipt: dict[str, Any]) -> tuple[str, str, str, str, str, str, str, int]:
    return (
        str(receipt.get("case_id", "")),
        str(receipt.get("provider_family", "")),
        str(receipt.get("provider_id", "")),
        str(receipt.get("method", "")),
        _canonical_json(list(receipt.get("params", []))) if "params" in receipt else "[]",
        str(receipt.get("request_sha256", "")),
        "" if receipt.get("response_sha256") in (None, "") else str(receipt.get("response_sha256", "")),
        int(receipt.get("attempt", 0) or 0),
    )


def _load_manifest_bound_frame(paths, spec: dict[str, Any]) -> pd.DataFrame:
    path = _safe_run_path(paths, str(spec["path"]))
    if _sha256_file(path) != str(spec["sha256"]):
        raise ValueError(f"hash mismatch for {path.name}")
    if spec["format"] == "json":
        payload = _read_json(path)
        return pd.DataFrame(payload)
    return _safe_read_csv(path)


def _load_manifest_bound_json(paths, spec: dict[str, Any]) -> Any:
    path = _safe_run_path(paths, str(spec["path"]))
    if _sha256_file(path) != str(spec["sha256"]):
        raise ValueError(f"hash mismatch for {path.name}")
    return _read_json(path)


def _packet_sha256(
    *,
    packet_type: str,
    source_manifest_sha256: str,
    visible_payload: dict[str, Any],
    blinding_seed_sha256: str,
) -> str:
    return _sha256_bytes(
        json.dumps(
            {
                "packet_type": packet_type,
                "source_manifest_sha256": source_manifest_sha256,
                "visible_payload": visible_payload,
                "blinding_seed_sha256": blinding_seed_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    )


def _validate_review_packets(
    *,
    packet_type: str,
    source_rows: pd.DataFrame,
    packets: list[dict[str, Any]],
) -> None:
    packet_ids = [str(packet.get("packet_id", "")) for packet in packets]
    if len(packet_ids) != len(set(packet_ids)):
        raise ValueError(f"duplicate {packet_type} packet_id detected")

    visible_fields = [field for field in REVIEW_VISIBLE_FIELDS if field in source_rows.columns]
    expected_packets: list[dict[str, Any]] = []
    for index, record in enumerate(source_rows.to_dict("records"), start=1):
        blinding_seed_sha256 = str(packets[index - 1]["blinding_seed_sha256"]) if index - 1 < len(packets) else ""
        visible_payload = {field: record.get(field) for field in visible_fields}
        expected_packets.append(
            {
                "packet_id": f"{packet_type}-{index:04d}",
                "packet_type": packet_type,
                "source_manifest_sha256": record.get("source_manifest_sha256", ""),
                "visible_fields": visible_fields,
                "visible_payload": visible_payload,
                "blinding_seed_sha256": blinding_seed_sha256,
                "assignment_placeholder": "",
                "packet_sha256": _packet_sha256(
                    packet_type=packet_type,
                    source_manifest_sha256=str(record.get("source_manifest_sha256", "")),
                    visible_payload=visible_payload,
                    blinding_seed_sha256=blinding_seed_sha256,
                ),
            }
        )

    if len(expected_packets) != len(packets):
        raise ValueError(f"{packet_type} packet count mismatch")
    for expected_packet, actual_packet in zip(expected_packets, packets, strict=True):
        if expected_packet != actual_packet:
            raise ValueError(f"{packet_type} packet payload differs from deterministic bundle")


def _validate_human_adjudication_handoff(
    *,
    paths: Any,
    manifest_path: Path,
    positive_packets: list[dict[str, Any]],
) -> None:
    manifest = _read_json(manifest_path)
    if manifest.get("status") != "ready_for_external_human_assignment":
        raise ValueError("human adjudication handoff has unsupported status")
    if int(manifest.get("case_count", -1)) != len(positive_packets):
        raise ValueError("human adjudication handoff case count mismatch")
    artifacts = manifest.get("artifacts")
    required_artifacts = {
        "positive_case_review_packets",
        "reviewer_a_response_template",
        "reviewer_b_response_template",
        "human_adjudication_protocol",
    }
    if not isinstance(artifacts, dict) or set(artifacts) != required_artifacts:
        raise ValueError("human adjudication handoff artifact set mismatch")
    loaded: dict[str, Any] = {}
    for name, spec in artifacts.items():
        if not isinstance(spec, dict) or set(spec) != {"path", "sha256"}:
            raise ValueError(f"human adjudication handoff artifact spec invalid: {name}")
        artifact_path = _safe_run_path(paths, str(spec["path"]))
        if _sha256_file(artifact_path) != str(spec["sha256"]):
            raise ValueError(f"human adjudication handoff artifact hash mismatch: {name}")
        loaded[name] = _read_json(artifact_path)
    if loaded["positive_case_review_packets"] != positive_packets:
        raise ValueError("human adjudication handoff packet artifact mismatch")

    expected_by_case = {
        str(packet["visible_payload"]["case_name"]): packet for packet in positive_packets
    }
    for role, name in (
        ("reviewer_a", "reviewer_a_response_template"),
        ("reviewer_b", "reviewer_b_response_template"),
    ):
        rows = loaded[name]
        if not isinstance(rows, list) or len(rows) != len(positive_packets):
            raise ValueError(f"human adjudication handoff template count mismatch: {role}")
        seen: set[str] = set()
        for row in rows:
            case_name = str(row.get("case_name", ""))
            packet = expected_by_case.get(case_name)
            if packet is None or case_name in seen:
                raise ValueError(f"human adjudication handoff template case mismatch: {role}")
            seen.add(case_name)
            if row.get("reviewer_role") != role:
                raise ValueError(f"human adjudication handoff role mismatch: {role}")
            if row.get("packet_id") != packet["packet_id"] or row.get("packet_sha256") != packet["packet_sha256"]:
                raise ValueError(f"human adjudication handoff packet binding mismatch: {role}")

    protocol = loaded["human_adjudication_protocol"]
    if int(protocol.get("case_count", -1)) != len(positive_packets):
        raise ValueError("human adjudication protocol case count mismatch")
    if protocol.get("final_status") != "FINALIZED_INDEPENDENT_ADJUDICATION":
        raise ValueError("human adjudication protocol final status mismatch")


def _validate_ai_only_adjudication_track(
    *,
    paths: Any,
    track_dir: Path,
    positive_packets: list[dict[str, Any]],
) -> dict[str, Any]:
    manifest_path = track_dir / "ai_adjudication_manifest.json"
    manifest = _read_json(manifest_path)
    if manifest.get("track_name") != AI_TRACK_NAME:
        raise ValueError("AI-only adjudication track name mismatch")
    if manifest.get("claim_authority") != "ANALYTIC_ONLY_NON_HUMAN":
        raise ValueError("AI-only adjudication claim authority mismatch")
    if manifest.get("human_independent_adjudication_counter_effect") != HUMAN_COUNTER_EFFECT:
        raise ValueError("AI-only adjudication attempts to affect the human counter")
    expected_manifest_sha = _sha256_bytes(
        json.dumps(
            {key: manifest[key] for key in sorted(manifest) if key != "manifest_sha256"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    )
    if manifest.get("manifest_sha256") != expected_manifest_sha:
        raise ValueError("AI-only adjudication manifest SHA-256 mismatch")

    artifacts = manifest.get("artifacts")
    required = {
        "evidence_packets",
        "protocol",
        "run_templates",
        "results",
        "summary",
        "author_signoff",
        "protocol_amendment",
    }
    completed_evidence = {
        "primary_a_results",
        "primary_b_results",
        "adjudicator_request",
        "adjudicator_results",
        "sensitivity_results",
    }
    expected = required | completed_evidence if manifest.get("status") == "COMPLETE" else required
    if not isinstance(artifacts, dict) or set(artifacts) != expected:
        raise ValueError("AI-only adjudication artifact set mismatch")
    loaded: dict[str, Any] = {}
    resolved_track_dir = track_dir.resolve()
    for name, spec in artifacts.items():
        if not isinstance(spec, dict) or set(spec) != {"path", "sha256"}:
            raise ValueError(f"AI-only adjudication artifact spec invalid: {name}")
        artifact_path = (track_dir / str(spec["path"])).resolve()
        if resolved_track_dir not in artifact_path.parents:
            raise ValueError(f"AI-only adjudication artifact path escapes track: {name}")
        if _sha256_file(artifact_path) != str(spec["sha256"]):
            raise ValueError(f"AI-only adjudication artifact hash mismatch: {name}")
        if artifact_path.suffix == ".json":
            loaded[name] = _read_json(artifact_path)

    protocol = loaded["protocol"]
    ai_evidence_packets = loaded["evidence_packets"]
    results = loaded["results"]
    summary = loaded["summary"]
    signoff = loaded["author_signoff"]
    if not isinstance(ai_evidence_packets, list) or len(ai_evidence_packets) != manifest.get("case_count"):
        raise ValueError("AI-only evidence packet cardinality mismatch")
    forbidden = {
        "mechanism_raw",
        "protocol_family",
        "primary_root_cause",
        "review_decision_status",
        "outcome_adjudication_id",
    }
    if any(
        forbidden.intersection((packet.get("visible_payload") or {}).keys())
        for packet in ai_evidence_packets
        if isinstance(packet, dict)
    ):
        raise ValueError("AI-only evidence packet exposes seed or outcome labels")
    if protocol.get("human_independent_adjudication_counter_effect") != HUMAN_COUNTER_EFFECT:
        raise ValueError("AI-only protocol attempts to affect the human counter")
    regenerated = evaluate_ai_adjudications(
        rows=results,
        protocol=protocol,
        packets=ai_evidence_packets,
        author_signoff=signoff,
    )
    if summary != regenerated:
        raise ValueError("AI-only adjudication summary differs from deterministic regeneration")
    if summary.get("human_independent_adjudications", {}).get("observed") != 0:
        raise ValueError("AI-only adjudication summary promotes the human counter")
    return summary


def _validate_reviewer_rows(frame: pd.DataFrame, positive_packets: list[dict[str, Any]]) -> pd.Series:
    required_columns = [
        "case_name",
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
    missing = [column for column in required_columns if column not in frame.columns]
    if missing:
        raise ValueError(f"review adjudication rows missing columns: {missing}")

    def _is_sha256(value: object) -> bool:
        text = str(value or "").strip().lower()
        return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)

    packet_hashes_by_case = {
        str(packet.get("visible_payload", {}).get("case_name", "")).strip(): str(packet.get("packet_sha256", "")).strip().lower()
        for packet in positive_packets
        if isinstance(packet, dict) and isinstance(packet.get("visible_payload"), dict)
    }

    return frame.apply(
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


def evaluate_public_acquisition(
    *,
    output_root: Path,
    revision: str | None = None,
    run_id: str | None = None,
    latest: bool = False,
) -> dict[str, Any]:
    revision_value = revision or DEFAULT_REVISION
    output_root = Path(output_root).resolve()
    if run_id:
        paths = _run_paths(output_root, revision_value, run_id)
    else:
        if not latest:
            raise FileNotFoundError("explicit --run-id or --latest is required for verification")
        paths = _discover_latest_run(output_root, revision=revision_value if revision else None)
        if paths is None:
            raise FileNotFoundError("no public acquisition run found for verification")

    result: dict[str, Any] = {
        "run_id": paths.run_id,
        "revision": paths.revision,
        "structure_valid": True,
        "scientifically_complete": False,
        "release_ready": False,
        "integrity_failures": [],
        "scientific_gaps": [],
        "checks": [],
    }

    try:
        queue_manifest = _read_json(paths.report_dir / "case_queue_manifest.json")
        source_snapshot_path = _safe_run_path(paths, str(queue_manifest["source_snapshot_path"]))
        if _sha256_file(source_snapshot_path) != str(queue_manifest["source_snapshot_sha256"]):
            raise ValueError("source snapshot hash mismatch")
        queue_path = _safe_run_path(paths, str(queue_manifest["queue_csv_path"]))
        pilot_path = _safe_run_path(paths, str(queue_manifest["pilot_csv_path"]))
        if _sha256_file(queue_path) != str(queue_manifest["queue_csv_sha256"]):
            raise ValueError("queue csv hash mismatch")
        if _sha256_file(pilot_path) != str(queue_manifest["pilot_csv_sha256"]):
            raise ValueError("pilot csv hash mismatch")
        queue = _safe_read_csv(queue_path)
        pilot = _safe_read_csv(pilot_path)
        policy = _load_policy()
        expected_queue, expected_pilot = build_case_queue(_safe_read_csv(source_snapshot_path), policy, input_sha256=str(queue_manifest["input_sha256"]))
        queue_equal = _frame_equivalent(expected_queue, queue)
        pilot_equal = _frame_equivalent(expected_pilot, pilot)
        _record_check(result, name="queue_rows", required=417, observed=int(len(queue)), passed=len(queue) == 417)
        _record_check(result, name="pilot_rows", required=9, observed=int(len(pilot)), passed=len(pilot) == 9)
        _record_check(result, name="queue_recomputed", required=True, observed=queue_equal, passed=queue_equal)
        _record_check(result, name="pilot_recomputed", required=True, observed=pilot_equal, passed=pilot_equal)
        if not queue_equal:
            _integrity_error(result, "case_queue differs from deterministic recomputation")
        if not pilot_equal:
            _integrity_error(result, "pilot_case_queue differs from deterministic recomputation")
        if len(queue) != 417:
            _integrity_error(result, "queue does not contain 417 cases")
        if queue["case_id"].duplicated().any():
            _integrity_error(result, "duplicate case_id values in case_queue")
        arbitrum_shortfall = bool((queue["chain"] == "arbitrum").any() and not queue.loc[queue["chain"] == "arbitrum", "allocation_satisfied"].all())
        _record_check(result, name="arbitrum_shortfall_preserved", required=True, observed=arbitrum_shortfall, passed=arbitrum_shortfall)
        if not arbitrum_shortfall:
            _integrity_error(result, "arbitrum pilot shortfall was not preserved")
        amendment_a2_observed, amendment_a2_complete = _evaluate_amendment_a2_pilot(Path(output_root))
        _record_check(
            result,
            name="evidence_grade_pilot_amendment_a2",
            required="complete 10-case A2 pilot with chain allocation {'arbitrum': 3, 'base': 1, 'bsc': 3, 'ethereum': 3}",
            observed=amendment_a2_observed,
            passed=amendment_a2_complete,
        )
        if len(pilot) != 10 and not amendment_a2_complete:
            result["scientific_gaps"].append("pilot remains scientifically incomplete: 9 cases selected with one Arbitrum shortfall")
    except Exception as exc:  # noqa: BLE001
        _integrity_error(result, f"queue verification failed: {exc}")
        queue = pd.DataFrame()
        pilot = pd.DataFrame()

    ledger_path = paths.raw_dir / "acquisition_events.jsonl"
    if ledger_path.exists():
        try:
            ledger = AppendOnlyLedger(ledger_path)
            events = ledger.events()
            _record_check(result, name="acquisition_ledger", required="schema-valid append-only hash chain", observed=len(events), passed=True)
        except Exception as exc:  # noqa: BLE001
            _record_check(result, name="acquisition_ledger", required="schema-valid append-only hash chain", observed=str(exc), passed=False)
            _integrity_error(result, f"acquisition ledger invalid: {exc}")
    else:
        _record_check(result, name="acquisition_ledger", required="optional until rpc execute", observed="missing", passed=True)
        result["scientific_gaps"].append("public RPC acquisition has not produced an append-only scientific ledger")

    rpc_results_path = paths.report_dir / "rpc_case_results.json"
    rpc_receipts_path = paths.report_dir / "rpc_receipts.json"
    if rpc_results_path.exists() and rpc_receipts_path.exists():
        try:
            rpc_results = _read_json(rpc_results_path)
            rpc_receipts = _read_json(rpc_receipts_path)
            run_state = _read_json(paths.report_dir / "run_state.json")
            rpc_state = dict(run_state.get("cells", {}).get("rpc", {}).get("details", {}))
            results_rows = list(rpc_results.get("results", []))
            receipts = list(rpc_receipts.get("receipts", []))
            planned_count = int(rpc_state.get("cases_processed") or rpc_state.get("cases_planned") or rpc_results.get("summary", {}).get("cases_processed") or rpc_results.get("summary", {}).get("cases_planned") or 0)
            planned_queue = queue.head(planned_count) if planned_count > 0 else pd.DataFrame(columns=queue.columns)
            planned_case_ids = {str(case_id) for case_id in planned_queue.get("case_id", pd.Series(dtype=str)).astype(str).tolist()}
            result_case_ids = [str(row.get("case_id", "")) for row in results_rows]
            if len(result_case_ids) != len(set(result_case_ids)):
                raise ValueError("duplicate case results in rpc_case_results")
            unknown_case_ids = sorted(case_id for case_id in result_case_ids if case_id not in planned_case_ids)
            if unknown_case_ids:
                raise ValueError(f"unknown rpc case_id values: {unknown_case_ids}")
            if len(results_rows) != planned_count:
                raise ValueError(f"rpc result count mismatch: planned={planned_count} observed={len(results_rows)}")
            receipt_keys = []
            receipt_identity_keys = []
            referenced_raw_paths: set[Path] = set()
            receipts_by_case: dict[str, list[dict[str, Any]]] = {}
            for receipt in receipts:
                request_path = _safe_run_path(paths, str(receipt["request_path"]))
                if _sha256_file(request_path) != str(receipt["request_sha256"]):
                    raise ValueError(f"request artifact hash mismatch for {request_path.name}")
                if "method" in receipt and "params" in receipt:
                    request_sha256 = _sha256_bytes(
                        _canonical_request_bytes(str(receipt.get("method", "")), list(receipt.get("params", [])))
                    )
                    if request_sha256 != str(receipt["request_sha256"]):
                        raise ValueError(f"request reconstruction hash mismatch for {request_path.name}")
                response_sha256 = receipt.get("response_sha256")
                raw_response_value = receipt.get("raw_response_path")
                raw_response_path: Path | None = None
                if response_sha256 in (None, "") and raw_response_value in (None, ""):
                    http_status = receipt.get("http_status")
                    error_value = receipt.get("error")
                    error_text = "" if error_value in (None, "") else str(error_value).strip()
                    if (http_status is None or int(http_status) < 400) and not error_text:
                        raise ValueError("successful request-only receipt lacks response evidence")
                elif response_sha256 in (None, ""):
                    raise ValueError("response path present without response sha256")
                elif raw_response_value in (None, ""):
                    raise ValueError("response sha256 present without response path")
                else:
                    raw_response_path = _safe_run_path(paths, str(raw_response_value))
                    if _sha256_file(raw_response_path) != str(response_sha256):
                        raise ValueError(f"receipt response hash mismatch for {raw_response_path.name}")
                receipt_key = (
                    str(receipt.get("case_id", "")),
                    int(receipt.get("receipt_index", 0)),
                    str(receipt.get("request_sha256", "")),
                    "" if response_sha256 in (None, "") else str(response_sha256),
                )
                receipt_keys.append(receipt_key)
                receipt_identity_keys.append(_receipt_identity(receipt))
                if raw_response_path is not None:
                    referenced_raw_paths.add(raw_response_path.resolve())
                receipts_by_case.setdefault(str(receipt.get("case_id", "")), []).append(receipt)
            if len(receipt_keys) != len(set(receipt_keys)):
                raise ValueError("duplicate rpc receipt references detected")
            if len(receipt_identity_keys) != len(set(receipt_identity_keys)):
                raise ValueError("duplicate rpc receipt identities detected")
            for row in results_rows:
                row_status = str(row.get("status", ""))
                if row_status not in RPC_ACCEPTED_STATUSES:
                    raise ValueError(f"unsupported rpc status: {row_status}")
                cell_results = dict(row.get("cell_results", {}))
                missing_cells = [cell_name for cell_name in RPC_REQUIRED_CELLS if cell_name not in cell_results]
                if missing_cells:
                    raise ValueError(f"rpc cell_results missing cells for {row.get('case_id')}: {missing_cells}")
                if row_status == "NOT_ATTEMPTED":
                    if str(row.get("blocked_reason", "")).strip() != "deadline_exceeded_before_attempt":
                        raise ValueError(f"rpc not-attempted row missing explicit reason for {row.get('case_id')}")
                    if str(rpc_state.get("status", rpc_results.get("summary", {}).get("status", ""))) != "skipped_deadline":
                        raise ValueError("rpc not-attempted rows inconsistent with run-state status")
                nested_observations = _iter_provider_observations(
                    {
                        "capability_snapshot": row.get("capability_snapshot"),
                        "prediction_snapshot": row.get("prediction_snapshot"),
                    }
                )
                expected_identities = {
                    _nested_observation_identity(str(row.get("case_id", "")), observation) for observation in nested_observations
                }
                if expected_identities:
                    actual_identities = {_receipt_identity(receipt) for receipt in receipts_by_case.get(str(row.get("case_id", "")), [])}
                    if expected_identities != actual_identities:
                        raise ValueError(f"missing/unbound nested observations for {row.get('case_id')}")
            _record_check(result, name="rpc_cases_preserved", required="attempt/failure/terminal rows with explicit closure", observed=len(results_rows), passed=True)
            result_receipt_keys = [
                (
                    str(receipt.get("case_id", "")),
                    int(receipt.get("receipt_index", 0)),
                    str(receipt.get("request_sha256", "")),
                    "" if receipt.get("response_sha256") in (None, "") else str(receipt.get("response_sha256", "")),
                )
                for row in results_rows
                for receipt in list(row.get("receipts", []))
            ]
            if set(result_receipt_keys) != set(receipt_keys):
                raise ValueError("rpc receipt manifest does not match receipt references embedded in rpc_case_results")
            orphan_raw_paths = []
            responses_root = paths.raw_dir / "responses"
            if responses_root.exists():
                for response_file in responses_root.rglob("*.json"):
                    resolved = response_file.resolve()
                    if resolved not in referenced_raw_paths:
                        orphan_raw_paths.append(str(response_file))
            if orphan_raw_paths:
                raise ValueError(f"orphan raw response files detected: {orphan_raw_paths}")
            receipt_recovery = dict(rpc_results.get("summary", {}).get("receipt_recovery", {}))
            if receipt_recovery.get("performed"):
                audit_path = paths.report_dir / "rpc_receipt_recovery_audit.json"
                if not audit_path.exists():
                    raise ValueError("rpc receipt recovery audit missing")
                audit = _read_json(audit_path)
                if str(audit.get("pre_recovery_rpc_case_results_sha256", "")) != str(receipt_recovery.get("pre_recovery_rpc_case_results_sha256", "")):
                    raise ValueError("rpc receipt recovery audit not bound to input")
                if str(audit.get("post_recovery_rpc_case_results_sha256", "")) != _sha256_file(rpc_results_path):
                    raise ValueError("rpc receipt recovery audit post-results hash mismatch")
                if str(audit.get("post_recovery_rpc_receipts_sha256", "")) != _sha256_file(rpc_receipts_path):
                    raise ValueError("rpc receipt recovery audit post-receipts hash mismatch")
                if int(audit.get("recovered_receipt_count", 0) or 0) != len(receipts):
                    raise ValueError("rpc receipt recovery audit receipt count mismatch")
                request_only_count = sum(
                    1
                    for receipt in receipts
                    if receipt.get("response_sha256") in (None, "") and receipt.get("raw_response_path") in (None, "")
                )
                bindable_response_count = len(receipts) - request_only_count
                if int(audit.get("request_only_error_receipt_count", 0) or 0) != request_only_count:
                    raise ValueError("rpc receipt recovery audit request-only count mismatch")
                if int(audit.get("bindable_response_receipt_count", 0) or 0) != bindable_response_count:
                    raise ValueError("rpc receipt recovery audit response-bound count mismatch")
                if int(audit.get("nested_observation_count", 0) or 0) != bindable_response_count + request_only_count:
                    raise ValueError("rpc receipt recovery audit observation coverage mismatch")
            _record_check(result, name="rpc_receipts", required="manifest-bound raw response receipts", observed=len(receipts), passed=True)
            if any(str(row.get("status")) != "VERIFIED" for row in results_rows):
                result["scientific_gaps"].append("public RPC acquisition remains incomplete for at least one pilot case")
        except Exception as exc:  # noqa: BLE001
            _record_check(result, name="rpc_receipts", required="manifest-bound raw response receipts", observed=str(exc), passed=False)
            _integrity_error(result, f"rpc receipt verification failed: {exc}")
    else:
        _record_check(result, name="rpc_receipts", required="optional until rpc execute", observed="missing", passed=True)
        result["scientific_gaps"].append("public RPC raw response receipts are missing")

    denominator_path = paths.processed_dir / "deployment_denominator.csv"
    denominator_manifest_path = paths.report_dir / "denominator_manifest.json"
    denominator_audit_path = paths.report_dir / "denominator_audit.csv"
    denominator = pd.DataFrame()
    if denominator_path.exists() and denominator_manifest_path.exists() and denominator_audit_path.exists():
        try:
            denominator_manifest = _read_json(denominator_manifest_path)
            denominator = _safe_read_csv(denominator_path)
            audit = _safe_read_csv(denominator_audit_path)
            _validate_denominator_identity(denominator)
            if denominator_manifest.get("denominator_csv_sha256") != _sha256_file(denominator_path):
                raise ValueError("denominator csv hash mismatch")
            if denominator_manifest.get("audit_csv_sha256") != _sha256_file(denominator_audit_path):
                raise ValueError("denominator audit hash mismatch")
            _record_check(result, name="deployment_denominator", required="manifest-bound denominator without duplicate identities", observed=int(len(denominator)), passed=True)
            if not audit.empty and audit["shortfall"].fillna(0).astype(int).gt(0).any():
                result["scientific_gaps"].append("deployment denominator shortfall remains unresolved across one or more chains")
        except Exception as exc:  # noqa: BLE001
            _record_check(result, name="deployment_denominator", required="manifest-bound denominator without duplicate identities", observed=str(exc), passed=False)
            _integrity_error(result, f"deployment denominator verification failed: {exc}")
    else:
        _record_check(result, name="deployment_denominator", required="optional until denominator execute", observed="missing", passed=True)
        result["scientific_gaps"].append("deployment denominator artifacts are missing")

    controls_path = paths.processed_dir / "control_candidates.csv"
    if controls_path.exists() and controls_path.stat().st_size:
        try:
            controls = _safe_read_csv(controls_path)
            if controls.empty:
                raise pd.errors.EmptyDataError("control candidate file intentionally empty")
            revalidated = qualify_control_rows(controls)
            candidate_columns = [column for column in ("candidate_status", "qualified_control", "candidate_row_valid", "control_row_sha256") if column in controls.columns]
            if not revalidated[candidate_columns].equals(controls[candidate_columns]):
                raise ValueError("control candidates failed row-level revalidation")
            _record_check(result, name="control_candidates", required="deterministic control row revalidation", observed=int(len(controls)), passed=True)
            if not bool(controls.get("qualified_control", pd.Series(dtype=bool)).map(bool).any()):
                result["scientific_gaps"].append("qualified control packets are not yet available")
        except pd.errors.EmptyDataError:
            _record_check(result, name="control_candidates", required="deterministic control row revalidation", observed="empty", passed=True)
            result["scientific_gaps"].append("control candidate generation remains scientifically incomplete")
        except Exception as exc:  # noqa: BLE001
            _record_check(result, name="control_candidates", required="deterministic control row revalidation", observed=str(exc), passed=False)
            _integrity_error(result, f"control verification failed: {exc}")
    else:
        _record_check(result, name="control_candidates", required="optional until controls execute", observed="missing_or_empty", passed=True)
        result["scientific_gaps"].append("control candidate generation remains scientifically incomplete")

    positive_packets_path = paths.report_dir / "positive_case_review_packets.json"
    control_packets_path = paths.report_dir / "control_review_packets.json"
    handoff_manifest_path = paths.report_dir / "human_adjudication_handoff_manifest.json"
    reviewer_independence_path = paths.report_dir / "reviewer_independence.json"
    ai_track_dir = paths.report_dir / "ai_only_adjudication"
    if positive_packets_path.exists():
        try:
            positive_snapshot = pd.read_csv(_safe_run_path(paths, str(queue_manifest["positive_snapshot_path"])))
            actual_packets = _read_json(positive_packets_path)
            _validate_review_packets(packet_type="positive_case_review_packets", source_rows=positive_snapshot, packets=actual_packets)
            _record_check(result, name="positive_review_packets", required="deterministic positive packet bundle", observed=len(actual_packets), passed=True)
            if handoff_manifest_path.exists():
                _validate_human_adjudication_handoff(
                    paths=paths,
                    manifest_path=handoff_manifest_path,
                    positive_packets=actual_packets,
                )
                _record_check(
                    result,
                    name="human_adjudication_handoff",
                    required="manifest-bound two-reviewer handoff",
                    observed=len(actual_packets),
                    passed=True,
                )
            else:
                result["scientific_gaps"].append("human adjudication handoff package is missing")
        except Exception as exc:  # noqa: BLE001
            _record_check(result, name="positive_review_packets", required="deterministic positive packet bundle", observed=str(exc), passed=False)
            _integrity_error(result, f"positive review packet verification failed: {exc}")
    else:
        _record_check(result, name="positive_review_packets", required="optional until review-packets", observed="missing", passed=True)
        result["scientific_gaps"].append("positive review packets are missing")
    if control_packets_path.exists():
        try:
            control_rows = _safe_read_csv(controls_path)
            control_packets = _read_json(control_packets_path)
            _validate_review_packets(packet_type="control_review_packets", source_rows=control_rows, packets=control_packets)
            _record_check(result, name="control_review_packets", required="deterministic control packet bundle", observed=len(control_packets), passed=True)
        except Exception as exc:  # noqa: BLE001
            _record_check(result, name="control_review_packets", required="deterministic control packet bundle", observed=str(exc), passed=False)
            _integrity_error(result, f"control review packet verification failed: {exc}")
    if reviewer_independence_path.exists():
        try:
            reviewer_payload = _read_json(reviewer_independence_path)
            reviewer_status = str(reviewer_payload.get("status", ""))
            adjudication_rows = _read_json(paths.report_dir / "finalized_positive_adjudications.json")
            adjudication_frame = pd.DataFrame(adjudication_rows)
            if reviewer_status != "complete":
                if reviewer_status and reviewer_status != "waiting_external":
                    raise ValueError(f"unsupported reviewer_independence status: {reviewer_status}")
                _record_check(result, name="reviewer_independence", required="strict accountable reviewer artifacts", observed=reviewer_status or "missing_status", passed=True)
                result["scientific_gaps"].append("reviewer independence artifacts are still waiting on external human review")
            else:
                if adjudication_frame.empty:
                    raise ValueError("reviewer independence marked complete without adjudication rows")
                positive_packets = _read_json(positive_packets_path) if positive_packets_path.exists() else []
                valid_rows = _validate_reviewer_rows(adjudication_frame, positive_packets)
                if not bool(valid_rows.all()):
                    raise ValueError("reviewer independence adjudication rows failed strict validation")
                _record_check(result, name="reviewer_independence", required="strict accountable reviewer artifacts", observed=int(valid_rows.sum()), passed=True)
                if len(adjudication_frame) < len(positive_packets):
                    result["scientific_gaps"].append("reviewer independence artifacts do not yet cover every positive-case packet")
        except Exception as exc:  # noqa: BLE001
            _record_check(result, name="reviewer_independence", required="strict accountable reviewer artifacts", observed=str(exc), passed=False)
            _integrity_error(result, f"reviewer independence verification failed: {exc}")
    else:
        result["scientific_gaps"].append("reviewer independence artifact is missing")

    if ai_track_dir.exists():
        try:
            positive_packets = _read_json(positive_packets_path) if positive_packets_path.exists() else []
            ai_summary = _validate_ai_only_adjudication_track(
                paths=paths,
                track_dir=ai_track_dir,
                positive_packets=positive_packets,
            )
            _record_check(
                result,
                name="ai_only_adjudication_track",
                required="separate non-human counter with deterministic regeneration",
                observed=ai_summary["independently_ai_adjudicated"]["observed"],
                passed=True,
            )
            if not ai_summary["internal_progression_gate"]["passed"]:
                result["scientific_gaps"].append(
                    "AI-only internal progression gate is not passed: "
                    + str(ai_summary["internal_progression_gate"]["status"])
                )
        except Exception as exc:  # noqa: BLE001
            _record_check(
                result,
                name="ai_only_adjudication_track",
                required="separate non-human counter with deterministic regeneration",
                observed=str(exc),
                passed=False,
            )
            _integrity_error(result, f"AI-only adjudication verification failed: {exc}")
    else:
        result["scientific_gaps"].append("AI-only adjudication protocol amendment is missing")

    counter_path = paths.report_dir / "public_acquisition_counters.json"
    counter_manifest_path = paths.report_dir / "public_acquisition_counter_inputs.json"
    if counter_path.exists() and counter_manifest_path.exists():
        try:
            artifact = _read_json(counter_path)
            manifest = _read_json(counter_manifest_path)
            manifest_errors = validate_counter_input_manifest(manifest)
            if manifest_errors:
                raise ValueError(f"counter input manifest validation failed: {', '.join(manifest_errors)}")
            for input_spec in manifest.get("inputs", {}).values():
                if isinstance(input_spec, dict) and "path" in input_spec:
                    _safe_run_path(paths, str(input_spec["path"]))
            if canonical_manifest_sha256(manifest) != manifest["input_manifest_sha256"]:
                raise ValueError("counter input manifest sha256 mismatch")
            evidence = {
                "positive_cases": _projectable_positive_cases(_load_manifest_bound_frame(paths, manifest["inputs"]["positive_cases"])),
                "deployment_denominator": _load_manifest_bound_frame(paths, manifest["inputs"]["deployment_denominator"]),
                "control_rows": _load_manifest_bound_frame(paths, manifest["inputs"]["control_rows"]),
                "positive_case_review_packets": _load_manifest_bound_json(paths, manifest["inputs"]["positive_case_review_packets"]),
                "control_review_packets": _load_manifest_bound_json(paths, manifest["inputs"]["control_review_packets"]),
                "finalized_positive_adjudications": _load_manifest_bound_json(paths, manifest["inputs"]["finalized_positive_adjudications"]),
                "minimum_independent_r5_blocks": int(manifest["minimum_independent_r5_blocks"]),
                "counter_targets": manifest["counter_targets"],
            }
            if manifest.get("control_qualification_bundle") is not None:
                qualification_projection, qualification_verification = (
                    load_verified_control_qualification_bundle(
                        manifest, manifest_path=counter_manifest_path
                    )
                )
                if not _frame_equivalent(
                    evidence["control_rows"], qualification_projection
                ):
                    raise ValueError(
                        "control qualification bundle projection differs from control_rows"
                    )
                evidence["control_qualification_verification"] = (
                    qualification_verification
                )
            if manifest.get("historical_snapshot_verification") is not None:
                historical_projection = load_verified_historical_projection(
                    manifest,
                    manifest_path=counter_manifest_path,
                )
                evidence["positive_cases"] = overlay_historical_snapshot_projection(
                    evidence["positive_cases"],
                    historical_projection,
                )
            regenerated = build_counter_artifact(evidence, input_manifest_sha256=manifest["input_manifest_sha256"])
            if validate_counter_artifact(artifact):
                raise ValueError("counter artifact failed schema validation")
            if artifact != regenerated:
                raise ValueError("counter artifact differs from deterministic regeneration")
            projected = project_counters(evidence)
            release_rows = _read_json(paths.report_dir / "release_predicates.json")
            if release_rows != projected:
                raise ValueError("release predicates differ from deterministic regeneration")
            prerequisite_keys = (
                "historical_snapshots",
                "independent_adjudications",
                "deployment_denominator",
                "control_candidates",
                "qualified_controls",
                "independent_r5_blocks",
            )
            prerequisites_closed = all(bool(artifact["counters"][key]["passed"]) for key in prerequisite_keys)
            if not prerequisites_closed and int(artifact["counters"]["release_eligible_cases"]) != 0:
                raise ValueError("release_eligible_cases must remain zero until all gate proofs close")
            if not prerequisites_closed and int(projected["release_eligible_cases"]) != 0:
                raise ValueError("release predicates falsely project eligible cases before all gate proofs close")
            _record_check(result, name="counter_projection", required="manifest-bound deterministic counter artifact", observed=artifact["counters"], passed=True)
            if int(artifact["counters"]["release_eligible_cases"]) <= 0:
                result["scientific_gaps"].append("release predicates are unsatisfied; no release-eligible cases projected")
            if not bool(artifact["counters"]["independent_r5_blocks"]["passed"]):
                result["scientific_gaps"].append("R5 prerequisites are not satisfied")
            if not bool(projected["production_qualification"]["qualified"]):
                result["scientific_gaps"].append("counter regeneration shows the public evidence package is not production-qualified")
            result["release_ready"] = bool(projected["production_qualification"]["qualified"] and int(artifact["counters"]["release_eligible_cases"]) > 0)
        except Exception as exc:  # noqa: BLE001
            _record_check(result, name="counter_projection", required="manifest-bound deterministic counter artifact", observed=str(exc), passed=False)
            _integrity_error(result, f"counter artifact verification failed: {exc}")
    else:
        _record_check(result, name="counter_projection", required="optional until project", observed="missing", passed=True)
        result["scientific_gaps"].append("counter projection artifacts are missing")

    result["scientifically_complete"] = result["structure_valid"] and not result["scientific_gaps"]
    if result["scientifically_complete"]:
        result["release_ready"] = True

    payload_path = paths.report_dir / "verification.json"
    report_path = paths.report_dir / "verification.md"
    payload_path.write_text(_json_dumps(result), encoding="utf-8")
    _write_markdown_report(report_path, result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Independent verifier for the public acquisition workflow.")
    parser.add_argument("--output-root", type=Path, default=ROOT)
    parser.add_argument("--revision", default=DEFAULT_REVISION)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--latest", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = evaluate_public_acquisition(output_root=Path(args.output_root), revision=args.revision, run_id=args.run_id, latest=args.latest)
        print(_json_dumps(result))
        return 0 if result["structure_valid"] else 1
    except FileNotFoundError as exc:
        payload = {
            "run_id": "",
            "revision": args.revision,
            "structure_valid": False,
            "scientifically_complete": False,
            "release_ready": False,
            "integrity_failures": [str(exc)],
            "scientific_gaps": [],
            "checks": [],
        }
        print(_json_dumps(payload))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
