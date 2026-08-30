from __future__ import annotations

import json
from pathlib import Path

from chronosaudit_stage2.ai_adjudication import (
    AI_TRACK_NAME,
    assemble_ai_adjudication_rows,
    build_ai_evidence_packets,
    build_ai_track_package,
    evaluate_ai_adjudications,
    make_author_signoff_attestation_sha256,
    make_ai_decision_sha256,
    make_final_ai_binding_sha256,
)
from chronosaudit_stage2.public_acquisition.counters import build_review_bundle


def _packets() -> list[dict[str, object]]:
    import pandas as pd

    return build_review_bundle(
        pd.DataFrame(
            [
                {
                    "case_name": "case-1",
                    "incident_name": "Case One",
                    "chain": "ethereum",
                    "target_contract_address": "0x" + "11" * 20,
                    "incident_date": "2024-01-01",
                    "source_manifest_sha256": "a" * 64,
                }
            ]
        ),
        packet_type="positive_case_review_packets",
        blinding_seed="ai-track-test",
    )


def test_ai_evidence_packets_bind_references_and_exclude_seed_labels() -> None:
    packets = build_ai_evidence_packets(
        [
            {
                "case_name": "case-1",
                "case_id": "case-id-1",
                "incident_name": "Case One",
                "chain": "ethereum",
                "target_contract_address": "0x" + "11" * 20,
                "incident_date": "2024-01-01",
                "incident_contract_path": "src/test/CaseOne_exp.sol",
                "incident_reference_urls": '["https://example.test/postmortem"]',
                "incident_tx_hashes": '["0xabc"]',
                "incident_record_sha256": "a" * 64,
                "source_snapshot_sha256": "b" * 64,
                "mechanism_raw": "oracle manipulation",
                "review_decision_status": "forbidden downstream label",
            }
        ],
        source_snapshot_sha256="c" * 64,
    )

    assert len(packets) == 1
    packet = packets[0]
    assert packet["packet_type"] == "ai_evidence_packet_v1"
    assert packet["visible_payload"]["incident_reference_urls"] == [
        "https://example.test/postmortem"
    ]
    assert packet["visible_payload"]["incident_tx_hashes"] == ["0xabc"]
    assert "mechanism_raw" not in packet["visible_payload"]
    assert "review_decision_status" not in packet["visible_payload"]
    assert set(packet["excluded_seed_and_outcome_fields"]) >= {
        "mechanism_raw",
        "review_decision_status",
    }
    assert len(packet["packet_sha256"]) == 64


def test_ai_evidence_packets_can_embed_pinned_incident_source(tmp_path: Path) -> None:
    source = tmp_path / "src/test/CaseOne_exp.sol"
    source.parent.mkdir(parents=True)
    source.write_text("contract Exploit { function testExploit() external {} }\n")
    packets = build_ai_evidence_packets(
        [{"case_name": "case-1", "incident_contract_path": "src/test/CaseOne_exp.sol"}],
        source_snapshot_sha256="c" * 64,
        source_repository_root=tmp_path,
        source_repository_commit="1" * 40,
    )
    payload = packets[0]["visible_payload"]
    assert payload["incident_source_status"] == "PINNED_SOURCE_PRESENT"
    assert payload["incident_source_repository_commit"] == "1" * 40
    assert payload["incident_source_text"].startswith("contract Exploit")
    assert len(payload["incident_source_sha256"]) == 64


def _run_specs() -> tuple[list[dict[str, object]], dict[str, object]]:
    primaries = [
        {
            "role": "primary_a",
            "run_id": "primary-a-v1",
            "provider": "provider-a",
            "model_id": "model-a",
            "model_version": "2026-08-01",
            "prompt_id": "baseline-v1",
            "prompt_text": "Return one protocol family and one primary root cause from the supplied evidence only.",
            "temperature": 0,
            "seed": 101,
            "blind_to_peer_decisions": True,
        },
        {
            "role": "primary_b",
            "run_id": "primary-b-v1",
            "provider": "provider-b",
            "model_id": "model-b",
            "model_version": "2026-08-02",
            "prompt_id": "baseline-v1",
            "prompt_text": "Return one protocol family and one primary root cause from the supplied evidence only.",
            "temperature": 0,
            "seed": 202,
            "blind_to_peer_decisions": True,
        },
    ]
    adjudicator = {
        "role": "adjudicator",
        "run_id": "adjudicator-c-v1",
        "provider": "provider-c",
        "model_id": "model-c",
        "model_version": "2026-08-03",
        "prompt_id": "adjudicator-v1",
        "prompt_text": "Resolve a frozen disagreement using packet evidence and both decisions; preserve uncertainty.",
        "temperature": 0,
        "seed": 303,
        "blind_to_peer_decisions": False,
    }
    return primaries, adjudicator


def test_package_is_separate_non_authoritative_and_hash_bound(tmp_path: Path) -> None:
    packets = _packets()
    primary_specs, adjudicator_spec = _run_specs()
    codebook = tmp_path / "reviewer_codebook.yaml"
    codebook.write_text("version: test\n", encoding="utf-8")

    manifest = build_ai_track_package(
        packets=packets,
        codebook_path=codebook,
        output_dir=tmp_path / "track",
        primary_run_specs=primary_specs,
        adjudicator_run_spec=adjudicator_spec,
        evidence_sufficiency="INSUFFICIENT_FOR_DEFENSIBLE_ROOT_CAUSE_RUNS",
    )

    assert manifest["track_name"] == AI_TRACK_NAME
    assert manifest["status"] == "READY_NOT_EXECUTED"
    assert manifest["case_count"] == 1
    assert manifest["human_independent_adjudication_counter_effect"] == "NONE"
    assert manifest["claim_authority"] == "ANALYTIC_ONLY_NON_HUMAN"
    assert set(manifest["artifacts"]) == {
        "evidence_packets",
        "protocol",
        "run_templates",
        "results",
        "summary",
        "author_signoff",
    }
    for spec in manifest["artifacts"].values():
        assert len(spec["sha256"]) == 64
        assert (tmp_path / "track" / spec["path"]).exists()

    protocol = json.loads((tmp_path / "track" / "ai_adjudication_protocol.json").read_text())
    assert protocol["primary_runs"][0]["prompt_sha256"] == protocol["primary_runs"][1]["prompt_sha256"]
    assert protocol["adjudicator_run"]["model_id"] not in {"model-a", "model-b"}
    assert protocol["limitations"][0].startswith("AI outputs are not human")
    signoff = json.loads((tmp_path / "track" / "accountable_author_signoff.json").read_text())
    assert signoff["status"] == "PENDING_HASH_BOUND_AUTHOR_SIGNOFF"
    assert signoff["authorization_basis"] == "USER_DIRECTIVE_IN_CURRENT_CODEX_TASK"


def _decision(run: dict[str, object], packet: dict[str, object], *, mechanism: str, confidence: str = "high") -> dict[str, object]:
    decision: dict[str, object] = {
        "run_id": run["run_id"],
        "provider": run["provider"],
        "model_id": run["model_id"],
        "model_version": run["model_version"],
        "prompt_id": run["prompt_id"],
        "prompt_sha256": run["prompt_sha256"],
        "packet_sha256": packet["packet_sha256"],
        "started_at_utc": "2026-08-17T10:00:00Z",
        "completed_at_utc": "2026-08-17T10:01:00Z",
        "blind_to_peer_decisions": run["blind_to_peer_decisions"],
        "protocol_family": "dex",
        "primary_root_cause": mechanism,
        "decision_rationale": "Bound test rationale.",
        "evidence_references": ["evidence:1"],
        "confidence": confidence,
    }
    decision["decision_sha256"] = make_ai_decision_sha256(decision)
    return decision


def test_valid_consensus_is_counted_only_in_ai_track(tmp_path: Path) -> None:
    packets = _packets()
    primary_specs, adjudicator_spec = _run_specs()
    codebook = tmp_path / "reviewer_codebook.yaml"
    codebook.write_text("version: test\n", encoding="utf-8")
    build_ai_track_package(
        packets=packets,
        codebook_path=codebook,
        output_dir=tmp_path / "track",
        primary_run_specs=primary_specs,
        adjudicator_run_spec=adjudicator_spec,
        evidence_sufficiency="SUFFICIENT_FOR_PROTOCOL_TEST_FIXTURE_ONLY",
    )
    protocol = json.loads((tmp_path / "track" / "ai_adjudication_protocol.json").read_text())
    row: dict[str, object] = {
        "case_name": "case-1",
        "packet_sha256": packets[0]["packet_sha256"],
        "primary_a": _decision(protocol["primary_runs"][0], packets[0], mechanism="access_control"),
        "primary_b": _decision(protocol["primary_runs"][1], packets[0], mechanism="access_control"),
        "agreement_status": "AI_MODEL_CONSENSUS",
        "adjudicator": None,
        "final_protocol_family": "dex",
        "final_primary_root_cause": "access_control",
        "final_confidence": "high",
        "finalized_at_utc": "2026-08-17T10:02:00Z",
        "human_independent_adjudication_counter_effect": "NONE",
    }
    row["final_ai_binding_sha256"] = make_final_ai_binding_sha256(row)

    summary = evaluate_ai_adjudications(rows=[row], protocol=protocol, packets=packets)

    assert summary["valid_completed_cases"] == 1
    assert summary["ai_adjudications"]["observed"] == 1
    assert summary["human_independent_adjudications"]["observed"] == 0
    assert summary["human_independent_adjudications"]["counter_effect"] == "NONE"
    assert summary["reliability"]["mechanism_raw_agreement"] == 1.0


def test_disagreement_requires_distinct_adjudicator_and_sensitivity_is_reported(tmp_path: Path) -> None:
    packets = _packets()
    primary_specs, adjudicator_spec = _run_specs()
    codebook = tmp_path / "reviewer_codebook.yaml"
    codebook.write_text("version: test\n", encoding="utf-8")
    build_ai_track_package(
        packets=packets,
        codebook_path=codebook,
        output_dir=tmp_path / "track",
        primary_run_specs=primary_specs,
        adjudicator_run_spec=adjudicator_spec,
        evidence_sufficiency="SUFFICIENT_FOR_PROTOCOL_TEST_FIXTURE_ONLY",
    )
    protocol = json.loads((tmp_path / "track" / "ai_adjudication_protocol.json").read_text())
    primary_a = _decision(protocol["primary_runs"][0], packets[0], mechanism="access_control")
    primary_b = _decision(protocol["primary_runs"][1], packets[0], mechanism="oracle")
    adjudicator = _decision(protocol["adjudicator_run"], packets[0], mechanism="access_control")
    adjudicator["blind_to_peer_decisions"] = False
    adjudicator["decision_sha256"] = make_ai_decision_sha256(adjudicator)
    row: dict[str, object] = {
        "case_name": "case-1",
        "packet_sha256": packets[0]["packet_sha256"],
        "primary_a": primary_a,
        "primary_b": primary_b,
        "agreement_status": "AI_DISAGREEMENT_ADJUDICATED",
        "adjudicator": adjudicator,
        "final_protocol_family": "dex",
        "final_primary_root_cause": "access_control",
        "final_confidence": "medium",
        "finalized_at_utc": "2026-08-17T10:03:00Z",
        "human_independent_adjudication_counter_effect": "NONE",
        "sensitivity_runs": [
            {"variant_id": "exclude_low_confidence", "primary_root_cause": "access_control"},
            {"variant_id": "alternate_prompt", "primary_root_cause": "oracle"},
        ],
    }
    row["final_ai_binding_sha256"] = make_final_ai_binding_sha256(row)
    summary = evaluate_ai_adjudications(rows=[row], protocol=protocol, packets=packets)
    assert summary["valid_completed_cases"] == 1
    assert summary["disagreements"] == 1
    assert summary["sensitivity"]["alternate_prompt_stability"] == 0.0

    bad = json.loads(json.dumps(row))
    bad["adjudicator"]["run_id"] = bad["primary_a"]["run_id"]
    bad["adjudicator"]["decision_sha256"] = make_ai_decision_sha256(bad["adjudicator"])
    bad["final_ai_binding_sha256"] = make_final_ai_binding_sha256(bad)
    rejected = evaluate_ai_adjudications(rows=[bad], protocol=protocol, packets=packets)
    assert rejected["valid_completed_cases"] == 0
    assert any("adjudicator" in error for error in rejected["validation_errors"])


def test_internal_progression_requires_hash_bound_named_author_signoff(tmp_path: Path) -> None:
    packets = _packets()
    primary_specs, adjudicator_spec = _run_specs()
    codebook = tmp_path / "reviewer_codebook.yaml"
    codebook.write_text("version: test\n", encoding="utf-8")
    build_ai_track_package(
        packets=packets,
        codebook_path=codebook,
        output_dir=tmp_path / "track",
        primary_run_specs=primary_specs,
        adjudicator_run_spec=adjudicator_spec,
        evidence_sufficiency="SUFFICIENT_FOR_PROTOCOL_TEST_FIXTURE_ONLY",
    )
    protocol = json.loads((tmp_path / "track" / "ai_adjudication_protocol.json").read_text())
    row: dict[str, object] = {
        "case_name": "case-1",
        "packet_sha256": packets[0]["packet_sha256"],
        "primary_a": _decision(protocol["primary_runs"][0], packets[0], mechanism="access_control"),
        "primary_b": _decision(protocol["primary_runs"][1], packets[0], mechanism="access_control"),
        "agreement_status": "AI_MODEL_CONSENSUS",
        "adjudicator": None,
        "final_protocol_family": "dex",
        "final_primary_root_cause": "access_control",
        "final_confidence": "high",
        "finalized_at_utc": "2026-08-17T10:02:00Z",
        "human_independent_adjudication_counter_effect": "NONE",
    }
    row["final_ai_binding_sha256"] = make_final_ai_binding_sha256(row)
    unsigned = evaluate_ai_adjudications(rows=[row], protocol=protocol, packets=packets)
    assert unsigned["internal_progression_gate"]["passed"] is False

    signoff: dict[str, object] = {
        "track_name": AI_TRACK_NAME,
        "status": "SIGNED_INTERNAL_PROGRESSION_AUTHORIZATION",
        "accountable_author_identity": "author-001",
        "signed_at_utc": "2026-08-17T11:00:00Z",
        "author_decision": "AUTHORIZE_INTERNAL_PROGRESSION",
        "protocol_sha256": protocol["protocol_sha256"],
        "results_sha256": unsigned["signoff_binding_inputs"]["results_sha256"],
        "reliability_and_sensitivity_sha256": unsigned["signoff_binding_inputs"][
            "reliability_and_sensitivity_sha256"
        ],
    }
    signoff["signature_or_attestation_sha256"] = make_author_signoff_attestation_sha256(signoff)
    signed = evaluate_ai_adjudications(
        rows=[row], protocol=protocol, packets=packets, author_signoff=signoff
    )
    assert signed["internal_progression_gate"]["passed"] is True
    assert signed["internal_progression_gate"]["permits"] == [
        "internal_analysis",
        "engineering",
        "manuscript_draft_preparation",
    ]
    assert signed["human_independent_adjudications"]["observed"] == 0


def test_assemble_ai_rows_requires_adjudicator_only_for_disagreement(tmp_path: Path) -> None:
    packets = _packets()
    primary_specs, adjudicator_spec = _run_specs()
    codebook = tmp_path / "reviewer_codebook.yaml"
    codebook.write_text("version: test\n", encoding="utf-8")
    build_ai_track_package(
        packets=packets,
        codebook_path=codebook,
        output_dir=tmp_path / "track",
        primary_run_specs=primary_specs,
        adjudicator_run_spec=adjudicator_spec,
        evidence_sufficiency="SUFFICIENT_FOR_PROTOCOL_TEST_FIXTURE_ONLY",
    )
    protocol = json.loads((tmp_path / "track" / "ai_adjudication_protocol.json").read_text())
    primary_a = _decision(protocol["primary_runs"][0], packets[0], mechanism="access_control")
    primary_b = _decision(protocol["primary_runs"][1], packets[0], mechanism="oracle")
    try:
        assemble_ai_adjudication_rows(
            packets=packets,
            primary_a_results=[primary_a],
            primary_b_results=[primary_b],
            adjudicator_results=[],
            sensitivity_results=[],
            finalized_at_utc="2026-08-17T10:03:00Z",
        )
    except ValueError as exc:
        assert "missing adjudicator" in str(exc)
    else:
        raise AssertionError("disagreement without adjudicator must fail")

    adjudicator = _decision(protocol["adjudicator_run"], packets[0], mechanism="access_control")
    adjudicator["blind_to_peer_decisions"] = False
    adjudicator["decision_sha256"] = make_ai_decision_sha256(adjudicator)
    rows = assemble_ai_adjudication_rows(
        packets=packets,
        primary_a_results=[primary_a],
        primary_b_results=[primary_b],
        adjudicator_results=[adjudicator],
        sensitivity_results=[
            {
                "packet_sha256": packets[0]["packet_sha256"],
                "variant_id": "alternate_prompt",
                "primary_root_cause": "access_control",
            }
        ],
        finalized_at_utc="2026-08-17T10:03:00Z",
    )
    assert rows[0]["agreement_status"] == "AI_DISAGREEMENT_ADJUDICATED"
    assert rows[0]["final_primary_root_cause"] == "access_control"
    assert rows[0]["final_ai_binding_sha256"] == make_final_ai_binding_sha256(rows[0])
