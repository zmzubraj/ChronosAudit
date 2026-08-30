from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any

from .review_workflow import _agreement, _gwet_ac1, _kappa, _krippendorff_alpha_nominal

AI_TRACK_NAME = "AI_ONLY_TRIANGULATION_V1"
AI_TRACK_SCHEMA_VERSION = "2026-08-17.ai-only-adjudication.v1"
AI_CONFIDENCE = {"high", "medium", "low"}
HUMAN_COUNTER_EFFECT = "NONE"

AI_EVIDENCE_VISIBLE_FIELDS = (
    "case_name",
    "case_id",
    "incident_name",
    "chain",
    "target_contract_address",
    "incident_date",
    "fork_block_number",
    "incident_contract_path",
    "source_url",
    "source_snapshot_sha256",
    "incident_record_sha256",
    "incident_reference_urls",
    "incident_tx_hashes",
    "incident_source_status",
    "incident_source_repository_commit",
    "incident_source_sha256",
    "incident_source_text",
)
AI_EVIDENCE_LIST_FIELDS = {"incident_reference_urls", "incident_tx_hashes"}
AI_EVIDENCE_EXCLUDED_FIELDS = (
    "mechanism_raw",
    "protocol_family",
    "primary_root_cause",
    "review_decision_status",
    "reviewer_a_decision",
    "reviewer_b_decision",
    "finalized_adjudication",
    "outcome_adjudication_id",
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _json_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text or text.lower() == "nan":
        return []
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return [text]
    if not isinstance(parsed, list):
        return [text]
    return [str(item).strip() for item in parsed if str(item).strip()]


def _clean_scalar(value: object) -> object:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() == "nan" else value


def build_ai_evidence_packets(
    source_rows: list[dict[str, Any]],
    *,
    source_snapshot_sha256: str,
    source_repository_root: Path | None = None,
    source_repository_commit: str = "",
) -> list[dict[str, Any]]:
    """Build label-blinded, hash-bound packets from the frozen positive-case snapshot."""
    if not _is_sha256(source_snapshot_sha256):
        raise ValueError("source_snapshot_sha256 must be a SHA-256 value")
    repository_root = source_repository_root.resolve() if source_repository_root is not None else None
    if repository_root is not None and (
        len(source_repository_commit) != 40
        or any(char not in "0123456789abcdef" for char in source_repository_commit.lower())
    ):
        raise ValueError("source_repository_commit must be a full Git commit SHA")
    packets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, record in enumerate(source_rows, start=1):
        case_name = str(record.get("case_name", "")).strip()
        if not case_name or case_name in seen:
            raise ValueError("AI evidence packets require unique non-empty case_name values")
        seen.add(case_name)
        visible_payload: dict[str, Any] = {}
        for field in AI_EVIDENCE_VISIBLE_FIELDS:
            if field.startswith("incident_source_"):
                continue
            value = record.get(field, "")
            visible_payload[field] = _json_list(value) if field in AI_EVIDENCE_LIST_FIELDS else _clean_scalar(value)
        source_status = "NOT_ACQUIRED"
        source_text = ""
        source_sha256 = ""
        if repository_root is not None:
            relative_source = str(record.get("incident_contract_path", "")).strip()
            candidate = (repository_root / relative_source).resolve() if relative_source else repository_root
            if relative_source and repository_root in candidate.parents and candidate.is_file():
                source_bytes = candidate.read_bytes()
                source_text = source_bytes.decode("utf-8", errors="replace")
                source_sha256 = hashlib.sha256(source_bytes).hexdigest()
                source_status = "PINNED_SOURCE_PRESENT"
            else:
                source_status = "PINNED_SOURCE_MISSING"
        visible_payload.update(
            {
                "incident_source_status": source_status,
                "incident_source_repository_commit": source_repository_commit if repository_root else "",
                "incident_source_sha256": source_sha256,
                "incident_source_text": source_text,
            }
        )
        packet_material = {
            "packet_type": "ai_evidence_packet_v1",
            "source_snapshot_sha256": source_snapshot_sha256.lower(),
            "visible_payload": visible_payload,
            "excluded_seed_and_outcome_fields": list(AI_EVIDENCE_EXCLUDED_FIELDS),
        }
        packets.append(
            {
                "packet_id": f"ai-evidence-{index:04d}",
                **packet_material,
                "visible_fields": list(AI_EVIDENCE_VISIBLE_FIELDS),
                "packet_sha256": _sha256_json(packet_material),
            }
        )
    return packets


def _parse_utc(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed


def _valid_interval(start: object, end: object) -> bool:
    start_at = _parse_utc(start)
    end_at = _parse_utc(end)
    return start_at is not None and end_at is not None and end_at > start_at


def _run_identity(run: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(run.get("run_id", "")),
        str(run.get("provider", "")),
        str(run.get("model_id", "")),
        str(run.get("model_version", "")),
    )


def _freeze_run_spec(spec: dict[str, Any]) -> dict[str, Any]:
    required = {
        "role",
        "run_id",
        "provider",
        "model_id",
        "model_version",
        "prompt_id",
        "prompt_text",
        "temperature",
        "seed",
        "blind_to_peer_decisions",
    }
    missing = sorted(required - set(spec))
    if missing:
        raise ValueError(f"AI run spec missing fields: {missing}")
    frozen = {key: spec[key] for key in sorted(required)}
    if any(not str(frozen[key]).strip() for key in ("role", "run_id", "provider", "model_id", "model_version", "prompt_id", "prompt_text")):
        raise ValueError("AI run spec identity and prompt fields must be non-empty")
    frozen["prompt_sha256"] = hashlib.sha256(str(frozen["prompt_text"]).encode("utf-8")).hexdigest()
    frozen["run_spec_sha256"] = _sha256_json(frozen)
    return frozen


def make_ai_decision_sha256(decision: dict[str, Any]) -> str:
    return _sha256_json({key: decision[key] for key in sorted(decision) if key != "decision_sha256"})


def make_final_ai_binding_sha256(row: dict[str, Any]) -> str:
    primary_a = row.get("primary_a") if isinstance(row.get("primary_a"), dict) else {}
    primary_b = row.get("primary_b") if isinstance(row.get("primary_b"), dict) else {}
    adjudicator = row.get("adjudicator") if isinstance(row.get("adjudicator"), dict) else {}
    payload = {
        "case_name": row.get("case_name", ""),
        "packet_sha256": row.get("packet_sha256", ""),
        "primary_a_decision_sha256": primary_a.get("decision_sha256", ""),
        "primary_b_decision_sha256": primary_b.get("decision_sha256", ""),
        "agreement_status": row.get("agreement_status", ""),
        "adjudicator_decision_sha256": adjudicator.get("decision_sha256", ""),
        "final_protocol_family": row.get("final_protocol_family", ""),
        "final_primary_root_cause": row.get("final_primary_root_cause", ""),
        "final_confidence": row.get("final_confidence", ""),
        "finalized_at_utc": row.get("finalized_at_utc", ""),
        "human_independent_adjudication_counter_effect": row.get(
            "human_independent_adjudication_counter_effect", ""
        ),
        "sensitivity_runs": row.get("sensitivity_runs", []),
    }
    return _sha256_json(payload)


def make_author_signoff_attestation_sha256(signoff: dict[str, Any]) -> str:
    fields = (
        "track_name",
        "status",
        "accountable_author_identity",
        "attestation_type",
        "authorization_source_sha256",
        "signed_at_utc",
        "author_decision",
        "protocol_sha256",
        "results_sha256",
        "reliability_and_sensitivity_sha256",
    )
    return _sha256_json({field: signoff.get(field, "") for field in fields})


def _index_decisions(
    values: list[dict[str, Any]], *, label: str
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for value in values:
        packet_sha = str(value.get("packet_sha256", "")).lower()
        if not _is_sha256(packet_sha) or packet_sha in indexed:
            raise ValueError(f"{label} contains an invalid or duplicate packet hash")
        indexed[packet_sha] = value
    return indexed


def assemble_ai_adjudication_rows(
    *,
    packets: list[dict[str, Any]],
    primary_a_results: list[dict[str, Any]],
    primary_b_results: list[dict[str, Any]],
    adjudicator_results: list[dict[str, Any]],
    sensitivity_results: list[dict[str, Any]],
    finalized_at_utc: str,
) -> list[dict[str, Any]]:
    """Join independently produced decisions without repairing or inventing labels."""
    if _parse_utc(finalized_at_utc) is None:
        raise ValueError("finalized_at_utc must be UTC")
    primary_a = _index_decisions(primary_a_results, label="primary_a_results")
    primary_b = _index_decisions(primary_b_results, label="primary_b_results")
    adjudicators = _index_decisions(adjudicator_results, label="adjudicator_results")
    sensitivities: dict[str, list[dict[str, Any]]] = {}
    for value in sensitivity_results:
        packet_sha = str(value.get("packet_sha256", "")).lower()
        if not _is_sha256(packet_sha):
            raise ValueError("sensitivity_results contains an invalid packet hash")
        sensitivities.setdefault(packet_sha, []).append(value)

    packet_hashes = [str(packet.get("packet_sha256", "")).lower() for packet in packets]
    expected = set(packet_hashes)
    if set(primary_a) != expected or set(primary_b) != expected:
        raise ValueError("primary result packet coverage differs from the evidence packets")
    if set(adjudicators) - expected or set(sensitivities) - expected:
        raise ValueError("adjudicator or sensitivity result contains an unexpected packet")

    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    confidence_name = {value: key for key, value in confidence_rank.items()}
    rows: list[dict[str, Any]] = []
    for packet in packets:
        packet_sha = str(packet["packet_sha256"]).lower()
        decision_a = primary_a[packet_sha]
        decision_b = primary_b[packet_sha]
        matches = (
            decision_a.get("protocol_family") == decision_b.get("protocol_family")
            and decision_a.get("primary_root_cause") == decision_b.get("primary_root_cause")
        )
        if matches:
            if packet_sha in adjudicators:
                raise ValueError("consensus packet has an unnecessary adjudicator")
            final_decision = decision_a
            agreement_status = "AI_MODEL_CONSENSUS"
            final_confidence = confidence_name[
                min(
                    confidence_rank.get(str(decision_a.get("confidence", "")).lower(), 0),
                    confidence_rank.get(str(decision_b.get("confidence", "")).lower(), 0),
                )
            ]
            adjudicator = None
        else:
            adjudicator = adjudicators.get(packet_sha)
            if adjudicator is None:
                raise ValueError(f"missing adjudicator for disagreement packet {packet_sha}")
            final_decision = adjudicator
            agreement_status = "AI_DISAGREEMENT_ADJUDICATED"
            final_confidence = str(adjudicator.get("confidence", "")).lower()
        row = {
            "case_name": packet["visible_payload"]["case_name"],
            "packet_sha256": packet_sha,
            "primary_a": decision_a,
            "primary_b": decision_b,
            "agreement_status": agreement_status,
            "adjudicator": adjudicator,
            "final_protocol_family": final_decision.get("protocol_family", ""),
            "final_primary_root_cause": final_decision.get("primary_root_cause", ""),
            "final_confidence": final_confidence,
            "finalized_at_utc": finalized_at_utc,
            "sensitivity_runs": sensitivities.get(packet_sha, []),
            "human_independent_adjudication_counter_effect": HUMAN_COUNTER_EFFECT,
        }
        row["final_ai_binding_sha256"] = make_final_ai_binding_sha256(row)
        rows.append(row)
    missing_adjudicators = set(adjudicators) - {
        row["packet_sha256"] for row in rows if row["agreement_status"] == "AI_DISAGREEMENT_ADJUDICATED"
    }
    if missing_adjudicators:
        raise ValueError("adjudicator results include non-disagreement packets")
    return rows


def _empty_summary(case_count: int, evidence_sufficiency: str) -> dict[str, Any]:
    return {
        "track_name": AI_TRACK_NAME,
        "status": "READY_NOT_EXECUTED",
        "evidence_sufficiency": evidence_sufficiency,
        "ai_adjudications": {"required": case_count, "observed": 0, "passed": False},
        "independently_ai_adjudicated": {"required": case_count, "observed": 0, "passed": False},
        "human_independent_adjudications": {
            "required": case_count,
            "observed": 0,
            "passed": False,
            "counter_effect": HUMAN_COUNTER_EFFECT,
        },
        "valid_completed_cases": 0,
        "validation_errors": [],
        "reliability": {},
        "sensitivity": {},
        "internal_progression_gate": {
            "status": "WAITING_AI_RUNS_AND_AUTHOR_SIGNOFF",
            "permits": [],
            "does_not_permit": ["human_adjudication_claim", "external_release_claim", "submission_readiness_claim"],
        },
    }


def build_ai_track_package(
    *,
    packets: list[dict[str, Any]],
    codebook_path: Path,
    output_dir: Path,
    primary_run_specs: list[dict[str, Any]],
    adjudicator_run_spec: dict[str, Any],
    sensitivity_run_spec: dict[str, Any] | None = None,
    evidence_sufficiency: str,
    protocol_amendment_path: Path | None = None,
) -> dict[str, Any]:
    if len(primary_run_specs) != 2:
        raise ValueError("AI-only track requires exactly two primary run specs")
    if not codebook_path.exists():
        raise FileNotFoundError(codebook_path)
    if any(not isinstance(packet.get("visible_payload"), dict) for packet in packets):
        raise ValueError("AI-only track packets must include visible_payload")
    case_names = [str(packet["visible_payload"].get("case_name", "")) for packet in packets]
    if any(not case_name for case_name in case_names) or len(case_names) != len(set(case_names)):
        raise ValueError("AI-only track packets require unique non-empty case_name values")

    primary_runs = [_freeze_run_spec(spec) for spec in primary_run_specs]
    adjudicator_run = _freeze_run_spec(adjudicator_run_spec)
    sensitivity_run = _freeze_run_spec(sensitivity_run_spec) if sensitivity_run_spec else None
    if {run["role"] for run in primary_runs} != {"primary_a", "primary_b"}:
        raise ValueError("AI primary roles must be primary_a and primary_b")
    if adjudicator_run["role"] != "adjudicator":
        raise ValueError("AI adjudicator role must be adjudicator")
    if not all(bool(run["blind_to_peer_decisions"]) for run in primary_runs):
        raise ValueError("AI primary runs must be blind to peer decisions")
    if len({_run_identity(run) for run in primary_runs}) != 2:
        raise ValueError("AI primary runs must use distinct frozen identities")
    if _run_identity(adjudicator_run) in {_run_identity(run) for run in primary_runs}:
        raise ValueError("AI adjudicator must use a distinct frozen model/run identity")
    if sensitivity_run is not None and sensitivity_run["role"] != "sensitivity":
        raise ValueError("AI sensitivity role must be sensitivity")

    output_dir.mkdir(parents=True, exist_ok=True)
    protocol = {
        "artifact_schema_version": AI_TRACK_SCHEMA_VERSION,
        "track_name": AI_TRACK_NAME,
        "track_type": "INDEPENDENT_AI_ONLY_ADJUDICATION",
        "claim_authority": "ANALYTIC_ONLY_NON_HUMAN",
        "human_independent_adjudication_counter_effect": HUMAN_COUNTER_EFFECT,
        "internal_progression_authority": {
            "permitted_after_gate_pass": ["internal_analysis", "engineering", "manuscript_draft_preparation"],
            "not_permitted": ["human_adjudication_claim", "external_release_claim", "submission_readiness_claim"],
            "author_signoff_required": True,
        },
        "case_count": len(packets),
        "evidence_sufficiency": evidence_sufficiency,
        "codebook_sha256": _sha256_file(codebook_path),
        "protocol_amendment_sha256": (
            _sha256_file(protocol_amendment_path) if protocol_amendment_path is not None else ""
        ),
        "primary_runs": primary_runs,
        "adjudicator_run": adjudicator_run,
        "sensitivity_run": sensitivity_run,
        "agreement_rules": {
            "consensus": "Both frozen primary decisions match on protocol_family and primary_root_cause.",
            "disagreement": "A distinct frozen adjudicator model/run resolves the disagreement after both primary decisions are frozen.",
            "minimum_reliability": 0.80,
        },
        "sensitivity_requirements": [
            "report all-case agreement and chance-corrected reliability",
            "report high-confidence-only agreement",
            "report alternate-prompt label stability",
            "preserve unresolved and low-confidence cases",
        ],
        "limitations": [
            "AI outputs are not human adjudications and cannot increment the independent-human-adjudication counter.",
            "Model diversity does not establish institutional, disciplinary, or real-world reviewer independence.",
            "Agreement can reflect shared training data, shared blind spots, prompt anchoring, or correlated model error.",
            "Internal progression does not establish external release, publication readiness, or venue compliance.",
            "The protocol and limitation must be disclosed in any external manuscript or submission package.",
        ],
    }
    protocol["protocol_sha256"] = _sha256_json(protocol)

    templates = [
        {
            "case_name": packet["visible_payload"]["case_name"],
            "packet_id": packet["packet_id"],
            "packet_sha256": packet["packet_sha256"],
            "primary_a": None,
            "primary_b": None,
            "agreement_status": "PENDING",
            "adjudicator": None,
            "final_protocol_family": "",
            "final_primary_root_cause": "",
            "final_confidence": "",
            "finalized_at_utc": "",
            "sensitivity_runs": [],
            "human_independent_adjudication_counter_effect": HUMAN_COUNTER_EFFECT,
            "final_ai_binding_sha256": "",
        }
        for packet in packets
    ]
    results: list[dict[str, Any]] = []
    author_signoff = {
        "artifact_schema_version": "2026-08-17.accountable-author-ai-gate-signoff.v1",
        "track_name": AI_TRACK_NAME,
        "authorization_basis": "USER_DIRECTIVE_IN_CURRENT_CODEX_TASK",
        "authorization_asserted": True,
        "accountable_author_identity": "",
        "signed_at_utc": "",
        "protocol_sha256": protocol["protocol_sha256"],
        "results_sha256": "",
        "reliability_and_sensitivity_sha256": "",
        "author_decision": "",
        "signature_or_attestation_sha256": "",
        "status": "PENDING_HASH_BOUND_AUTHOR_SIGNOFF",
        "note": "The current-session directive authorizes the protocol design but does not fabricate a named or signed accountable-author attestation.",
    }
    summary = evaluate_ai_adjudications(
        rows=results,
        protocol=protocol,
        packets=packets,
        author_signoff=author_signoff,
    )

    artifact_values = {
        "evidence_packets": ("ai_evidence_packets.json", packets),
        "protocol": ("ai_adjudication_protocol.json", protocol),
        "run_templates": ("ai_adjudication_run_templates.json", templates),
        "results": ("ai_adjudication_results.json", results),
        "summary": ("ai_adjudication_summary.json", summary),
        "author_signoff": ("accountable_author_signoff.json", author_signoff),
    }
    if protocol_amendment_path is not None:
        if not protocol_amendment_path.exists():
            raise FileNotFoundError(protocol_amendment_path)
        amendment_snapshot = output_dir / "ai_adjudication_protocol_amendment_v1.yaml"
        shutil.copy2(protocol_amendment_path, amendment_snapshot)
        artifact_values["protocol_amendment"] = (
            amendment_snapshot.name,
            None,
        )
    artifacts: dict[str, dict[str, str]] = {}
    for name, (filename, value) in artifact_values.items():
        path = output_dir / filename
        if value is not None:
            _write_json(path, value)
        artifacts[name] = {"path": filename, "sha256": _sha256_file(path)}

    manifest = {
        "artifact_schema_version": "2026-08-17.ai-only-adjudication-manifest.v1",
        "track_name": AI_TRACK_NAME,
        "status": "READY_NOT_EXECUTED",
        "case_count": len(packets),
        "claim_authority": "ANALYTIC_ONLY_NON_HUMAN",
        "human_independent_adjudication_counter_effect": HUMAN_COUNTER_EFFECT,
        "artifacts": artifacts,
    }
    manifest["manifest_sha256"] = _sha256_json(manifest)
    _write_json(output_dir / "ai_adjudication_manifest.json", manifest)
    return manifest


def _validate_decision(
    decision: object,
    *,
    frozen_run: dict[str, Any],
    packet_sha256: str,
    require_blind: bool,
) -> list[str]:
    if not isinstance(decision, dict):
        return ["missing decision object"]
    errors: list[str] = []
    for field in ("run_id", "provider", "model_id", "model_version", "prompt_id", "prompt_sha256"):
        if str(decision.get(field, "")) != str(frozen_run.get(field, "")):
            errors.append(f"{field} differs from frozen run")
    if str(decision.get("packet_sha256", "")).lower() != packet_sha256.lower():
        errors.append("packet_sha256 mismatch")
    if require_blind and decision.get("blind_to_peer_decisions") is not True:
        errors.append("primary run was not blinded")
    if not _valid_interval(decision.get("started_at_utc"), decision.get("completed_at_utc")):
        errors.append("invalid UTC model-run interval")
    for field in ("protocol_family", "primary_root_cause", "decision_rationale"):
        if not str(decision.get(field, "")).strip():
            errors.append(f"missing {field}")
    refs = decision.get("evidence_references")
    if not isinstance(refs, list) or not refs or any(not str(value).strip() for value in refs):
        errors.append("missing evidence_references")
    if str(decision.get("confidence", "")).lower() not in AI_CONFIDENCE:
        errors.append("invalid confidence")
    if not _is_sha256(decision.get("decision_sha256")) or decision.get("decision_sha256") != make_ai_decision_sha256(decision):
        errors.append("decision_sha256 mismatch")
    return errors


def evaluate_ai_adjudications(
    *,
    rows: list[dict[str, Any]],
    protocol: dict[str, Any],
    packets: list[dict[str, Any]],
    author_signoff: dict[str, Any] | None = None,
) -> dict[str, Any]:
    packet_by_case = {
        str(packet.get("visible_payload", {}).get("case_name", "")): packet
        for packet in packets
        if isinstance(packet.get("visible_payload"), dict)
    }
    if len(packet_by_case) != len(packets):
        raise ValueError("packets do not provide unique case bindings")
    primary_runs = {run["role"]: run for run in protocol.get("primary_runs", [])}
    adjudicator_run = protocol.get("adjudicator_run", {})
    sensitivity_run = protocol.get("sensitivity_run")
    validation_errors: list[str] = []
    valid_rows: list[dict[str, Any]] = []

    seen: set[str] = set()
    for row in rows:
        case_name = str(row.get("case_name", ""))
        errors: list[str] = []
        packet = packet_by_case.get(case_name)
        if packet is None:
            errors.append("unexpected case")
        if case_name in seen:
            errors.append("duplicate case")
        seen.add(case_name)
        packet_sha = str(packet.get("packet_sha256", "")) if packet else ""
        if str(row.get("packet_sha256", "")).lower() != packet_sha.lower():
            errors.append("row packet_sha256 mismatch")
        if row.get("human_independent_adjudication_counter_effect") != HUMAN_COUNTER_EFFECT:
            errors.append("human counter effect must be NONE")

        primary_a = row.get("primary_a")
        primary_b = row.get("primary_b")
        errors.extend(
            f"primary_a: {error}"
            for error in _validate_decision(
                primary_a,
                frozen_run=primary_runs.get("primary_a", {}),
                packet_sha256=packet_sha,
                require_blind=True,
            )
        )
        errors.extend(
            f"primary_b: {error}"
            for error in _validate_decision(
                primary_b,
                frozen_run=primary_runs.get("primary_b", {}),
                packet_sha256=packet_sha,
                require_blind=True,
            )
        )
        if isinstance(primary_a, dict) and isinstance(primary_b, dict) and _run_identity(primary_a) == _run_identity(primary_b):
            errors.append("primary model/run identities are not distinct")

        agreement_status = row.get("agreement_status")
        primary_match = (
            isinstance(primary_a, dict)
            and isinstance(primary_b, dict)
            and primary_a.get("protocol_family") == primary_b.get("protocol_family")
            and primary_a.get("primary_root_cause") == primary_b.get("primary_root_cause")
        )
        if agreement_status == "AI_MODEL_CONSENSUS":
            if not primary_match:
                errors.append("consensus status conflicts with primary decisions")
            if row.get("adjudicator") not in (None, {}):
                errors.append("consensus row must not contain adjudicator")
            expected_final = primary_a if isinstance(primary_a, dict) else {}
        elif agreement_status == "AI_DISAGREEMENT_ADJUDICATED":
            if primary_match:
                errors.append("adjudicated-disagreement status has matching primaries")
            adjudicator = row.get("adjudicator")
            errors.extend(
                f"adjudicator: {error}"
                for error in _validate_decision(
                    adjudicator,
                    frozen_run=adjudicator_run,
                    packet_sha256=packet_sha,
                    require_blind=False,
                )
            )
            if isinstance(adjudicator, dict):
                primary_identities = {
                    _run_identity(value) for value in (primary_a, primary_b) if isinstance(value, dict)
                }
                if _run_identity(adjudicator) in primary_identities:
                    errors.append("adjudicator model/run identity is not distinct")
            expected_final = adjudicator if isinstance(adjudicator, dict) else {}
        else:
            errors.append("unsupported agreement_status")
            expected_final = {}

        if row.get("final_protocol_family") != expected_final.get("protocol_family"):
            errors.append("final_protocol_family mismatch")
        if row.get("final_primary_root_cause") != expected_final.get("primary_root_cause"):
            errors.append("final_primary_root_cause mismatch")
        if str(row.get("final_confidence", "")).lower() not in AI_CONFIDENCE:
            errors.append("invalid final_confidence")
        finalized_at = _parse_utc(row.get("finalized_at_utc"))
        completed_values = [
            _parse_utc(value.get("completed_at_utc"))
            for value in (primary_a, primary_b, row.get("adjudicator"))
            if isinstance(value, dict)
        ]
        if finalized_at is None or any(value is None or finalized_at < value for value in completed_values):
            errors.append("finalized_at_utc precedes a model decision or is invalid")
        if not _is_sha256(row.get("final_ai_binding_sha256")) or row.get("final_ai_binding_sha256") != make_final_ai_binding_sha256(row):
            errors.append("final_ai_binding_sha256 mismatch")

        sensitivity_values = row.get("sensitivity_runs", [])
        if sensitivity_run is not None:
            if not isinstance(sensitivity_values, list) or len(sensitivity_values) != 1:
                errors.append("exactly one frozen sensitivity run is required")
            else:
                sensitivity_decision = sensitivity_values[0]
                if sensitivity_decision.get("variant_id") != "alternate_prompt":
                    errors.append("sensitivity variant_id must be alternate_prompt")
                errors.extend(
                    f"sensitivity: {error}"
                    for error in _validate_decision(
                        sensitivity_decision,
                        frozen_run=sensitivity_run,
                        packet_sha256=packet_sha,
                        require_blind=True,
                    )
                )

        if errors:
            validation_errors.extend(f"{case_name or '<missing>'}: {error}" for error in errors)
        else:
            valid_rows.append(row)

    protocol_count = int(protocol.get("case_count", len(packets)))
    primary_a_protocol = [str(row["primary_a"]["protocol_family"]) for row in valid_rows]
    primary_b_protocol = [str(row["primary_b"]["protocol_family"]) for row in valid_rows]
    primary_a_mechanism = [str(row["primary_a"]["primary_root_cause"]) for row in valid_rows]
    primary_b_mechanism = [str(row["primary_b"]["primary_root_cause"]) for row in valid_rows]
    reliability = {
        "protocol_raw_agreement": _agreement(primary_a_protocol, primary_b_protocol),
        "protocol_cohen_kappa": _kappa(primary_a_protocol, primary_b_protocol),
        "protocol_gwet_ac1": _gwet_ac1(primary_a_protocol, primary_b_protocol),
        "protocol_krippendorff_alpha_nominal": _krippendorff_alpha_nominal(
            primary_a_protocol, primary_b_protocol
        ),
        "mechanism_raw_agreement": _agreement(primary_a_mechanism, primary_b_mechanism),
        "mechanism_cohen_kappa": _kappa(primary_a_mechanism, primary_b_mechanism),
        "mechanism_gwet_ac1": _gwet_ac1(primary_a_mechanism, primary_b_mechanism),
        "mechanism_krippendorff_alpha_nominal": _krippendorff_alpha_nominal(
            primary_a_mechanism, primary_b_mechanism
        ),
    }
    high_confidence_rows = [row for row in valid_rows if row.get("final_confidence") == "high"]
    alternate_prompt_values: list[bool] = []
    for row in valid_rows:
        for sensitivity in row.get("sensitivity_runs", []):
            if sensitivity.get("variant_id") == "alternate_prompt":
                alternate_prompt_values.append(
                    sensitivity.get("primary_root_cause") == row.get("final_primary_root_cause")
                )
    sensitivity = {
        "high_confidence_case_count": len(high_confidence_rows),
        "high_confidence_fraction": len(high_confidence_rows) / len(valid_rows) if valid_rows else None,
        "alternate_prompt_evaluated_cases": len(alternate_prompt_values),
        "alternate_prompt_stability": (
            sum(alternate_prompt_values) / len(alternate_prompt_values) if alternate_prompt_values else None
        ),
    }
    sensitivity_passed = (
        sensitivity_run is None
        or (
            len(alternate_prompt_values) == protocol_count
            and sensitivity["alternate_prompt_stability"] is not None
        )
    )
    observed = len(valid_rows)
    ai_passed = observed == protocol_count and not validation_errors
    minimum = float(protocol.get("agreement_rules", {}).get("minimum_reliability", 0.80))
    reliability_passed = (
        reliability["protocol_raw_agreement"] is not None
        and reliability["mechanism_raw_agreement"] is not None
        and reliability["protocol_raw_agreement"] >= minimum
        and reliability["mechanism_raw_agreement"] >= minimum
    )
    results_sha256 = _sha256_json(rows)
    reliability_and_sensitivity_sha256 = _sha256_json(
        {
            "independently_ai_adjudicated": {
                "required": protocol_count,
                "observed": observed,
                "passed": ai_passed,
            },
            "reliability": reliability,
            "sensitivity": sensitivity,
            "validation_errors": validation_errors,
        }
    )
    signed = bool(
        author_signoff
        and author_signoff.get("track_name") == AI_TRACK_NAME
        and author_signoff.get("status") == "SIGNED_INTERNAL_PROGRESSION_AUTHORIZATION"
        and str(author_signoff.get("accountable_author_identity", "")).strip()
        and _parse_utc(author_signoff.get("signed_at_utc")) is not None
        and author_signoff.get("author_decision") == "AUTHORIZE_INTERNAL_PROGRESSION"
        and author_signoff.get("protocol_sha256") == protocol.get("protocol_sha256")
        and author_signoff.get("results_sha256") == results_sha256
        and author_signoff.get("reliability_and_sensitivity_sha256")
        == reliability_and_sensitivity_sha256
        and _is_sha256(author_signoff.get("signature_or_attestation_sha256"))
        and author_signoff.get("signature_or_attestation_sha256")
        == make_author_signoff_attestation_sha256(author_signoff)
    )
    gate_passed = ai_passed and reliability_passed and sensitivity_passed and signed
    if gate_passed:
        internal_gate_status = "PASS"
    elif not ai_passed:
        internal_gate_status = "WAITING_AI_RUNS"
    elif not sensitivity_passed:
        internal_gate_status = "WAITING_SENSITIVITY_RUNS"
    elif not reliability_passed:
        internal_gate_status = "FAIL_RELIABILITY_THRESHOLD"
    elif not signed:
        internal_gate_status = "WAITING_ACCOUNTABLE_AUTHOR_SIGNOFF"
    else:
        internal_gate_status = "FAIL_UNSPECIFIED_GATE"
    return {
        "track_name": AI_TRACK_NAME,
        "status": "COMPLETE" if ai_passed else ("PARTIAL" if observed else "READY_NOT_EXECUTED"),
        "evidence_sufficiency": protocol.get("evidence_sufficiency", "UNSPECIFIED"),
        "ai_adjudications": {"required": protocol_count, "observed": observed, "passed": ai_passed},
        "independently_ai_adjudicated": {
            "required": protocol_count,
            "observed": observed,
            "passed": ai_passed,
        },
        "human_independent_adjudications": {
            "required": protocol_count,
            "observed": 0,
            "passed": False,
            "counter_effect": HUMAN_COUNTER_EFFECT,
        },
        "valid_completed_cases": observed,
        "disagreements": sum(
            row.get("agreement_status") == "AI_DISAGREEMENT_ADJUDICATED" for row in valid_rows
        ),
        "validation_errors": validation_errors,
        "reliability": reliability,
        "reliability_gate_passed": reliability_passed,
        "sensitivity": sensitivity,
        "sensitivity_gate_passed": sensitivity_passed,
        "signoff_binding_inputs": {
            "protocol_sha256": protocol.get("protocol_sha256", ""),
            "results_sha256": results_sha256,
            "reliability_and_sensitivity_sha256": reliability_and_sensitivity_sha256,
        },
        "internal_progression_gate": {
            "status": internal_gate_status,
            "passed": gate_passed,
            "permits": ["internal_analysis", "engineering", "manuscript_draft_preparation"] if gate_passed else [],
            "does_not_permit": ["human_adjudication_claim", "external_release_claim", "submission_readiness_claim"],
            "author_signoff_verified": signed,
        },
        "claim_limitations": protocol.get("limitations", []),
    }
