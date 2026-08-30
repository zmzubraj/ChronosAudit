from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition.control_trace_retry_overlay import (
    CompleteTraceEvidence,
    ControlTraceRetryOverlayError,
    VerifiedTraceSourceRoot,
    build_complete_source_union,
    build_completion_overlay_from_verified,
    build_retry_targets_from_verified_sources,
    verify_retry_target_payload,
)


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _target(target_id: str) -> dict[str, object]:
    row: dict[str, object] = {
        "target_id": target_id,
        "case_id": "case-1",
        "chain": "ethereum",
        "chain_address": "ethereum:0x1111111111111111111111111111111111111111",
        "transaction_hash": "0x" + "1" * 64,
        "block_number": 1,
        "block_hash": "0x" + "2" * 64,
        "reserve_record_sha256": "3" * 64,
        "calls": [],
    }
    return row


def _complete(target: dict[str, object], source: str) -> CompleteTraceEvidence:
    row: dict[str, object] = {
        **{k: target[k] for k in (
            "target_id", "case_id", "chain", "chain_address", "transaction_hash",
            "block_number", "block_hash", "reserve_record_sha256",
        )},
        "target_sha256": _sha(target),
        "provider_ids": ["a", "b"],
        "operator_families": ["family-a", "family-b"],
        "creation_set": [[target["transaction_hash"], "0x1111111111111111111111111111111111111111", "create", None, "[]"]],
        "disposition": "complete",
    }
    row["creation_set_sha256"] = _sha(tuple(tuple(v) for v in row["creation_set"]))
    row["record_sha256"] = _sha(row)
    return CompleteTraceEvidence(
        target_id=str(target["target_id"]),
        source_key=source,
        checkpoint_file_sha256=source,
        record=dict(row),
    )


def _source(key: str, evidence: list[CompleteTraceEvidence]) -> VerifiedTraceSourceRoot:
    return VerifiedTraceSourceRoot(
        source_key=key,
        checkpoint_file_sha256=key,
        checkpoint_sha256="c" * 64,
        checkpoint_status="IN_PROGRESS_NON_AUTHORIZING",
        processed_target_count=len(evidence),
        completed_target_count=len(evidence),
        request_count=2 * len(evidence),
        complete_evidence=tuple(evidence),
        manifest={"source_key": key},
    )


def test_identical_complete_rows_choose_deterministic_canonical_source():
    target = _target("trace-1")
    union = build_complete_source_union(
        [_source("b", [_complete(target, "b")]), _source("a", [_complete(target, "a")])]
    )
    chosen = union.completed_by_target["trace-1"]
    assert chosen.canonical_source_key == "a"
    assert len(chosen.agreeing_sources) == 2


def test_conflicting_complete_rows_fail_closed():
    target = _target("trace-1")
    first = _complete(target, "a")
    second = _complete(target, "b")
    second.record["creation_set"] = []
    second.record["creation_set_sha256"] = _sha(())
    second.record["record_sha256"] = _sha({k: v for k, v in second.record.items() if k != "record_sha256"})
    with pytest.raises(ControlTraceRetryOverlayError, match="complete_source_conflict"):
        build_complete_source_union([_source("a", [first]), _source("b", [second])])


def test_retry_targets_are_original_minus_source_complete():
    targets = [_target("trace-1"), _target("trace-2")]
    union = build_complete_source_union([_source("a", [_complete(targets[0], "a")])])
    payload = build_retry_targets_from_verified_sources(
        original_targets=targets,
        original_targets_file_sha256="f" * 64,
        original_targets_sha256="e" * 64,
        activation_verification_file_sha256="d" * 64,
        activation_verification_sha256="c" * 64,
        spec_approval_record_sha256="b" * 64,
        sources=[_source("a", [_complete(targets[0], "a")])],
        union=union,
    )
    assert [row["target_id"] for row in payload["targets"]] == ["trace-2"]
    assert payload["source_complete_count"] == 1
    assert payload["unresolved_count"] == 1
    assert payload["rpc_call_count"] == 2
    assert payload["rpc_authorized"] is False
    verify_retry_target_payload(payload)


def test_retry_payload_rejects_source_complete_replay():
    targets = [_target("trace-1"), _target("trace-2")]
    source = _source("a", [_complete(targets[0], "a")])
    union = build_complete_source_union([source])
    payload = build_retry_targets_from_verified_sources(
        original_targets=targets,
        original_targets_file_sha256="f" * 64,
        original_targets_sha256="e" * 64,
        activation_verification_file_sha256="d" * 64,
        activation_verification_sha256="c" * 64,
        spec_approval_record_sha256="b" * 64,
        sources=[source],
        union=union,
    )
    payload["targets"].append(targets[0])
    material = {k: v for k, v in payload.items() if k != "retry_targets_sha256"}
    payload["retry_targets_sha256"] = _sha(material)
    with pytest.raises(ControlTraceRetryOverlayError, match="retry_contains_source_complete"):
        verify_retry_target_payload(payload)


def test_completion_overlay_covers_every_original_target_once():
    targets = [_target("trace-1"), _target("trace-2")]
    source = _source("a", [_complete(targets[0], "a")])
    union = build_complete_source_union([source])
    retry_payload = build_retry_targets_from_verified_sources(
        original_targets=targets,
        original_targets_file_sha256="f" * 64,
        original_targets_sha256="e" * 64,
        activation_verification_file_sha256="d" * 64,
        activation_verification_sha256="c" * 64,
        spec_approval_record_sha256="b" * 64,
        sources=[source],
        union=union,
    )
    retry_source = _source("retry", [_complete(targets[1], "retry")])
    retry_source = VerifiedTraceSourceRoot(
        **{**retry_source.__dict__, "checkpoint_status": "COMPLETE"}
    )
    overlay = build_completion_overlay_from_verified(
        original_targets=targets,
        source_union=union,
        retry_source=retry_source,
        retry_targets_payload=retry_payload,
        retry_targets_file_sha256="9" * 64,
        retry_targets_verification_sha256="8" * 64,
    )
    assert overlay["decision"] == "COMPLETE_NON_AUTHORIZING"
    assert overlay["completed_target_count"] == 2
    assert {row["evidence_origin"] for row in overlay["targets"]} == {
        "IMMUTABLE_SOURCE_ROOT", "FRESH_RETRY_ROOT"
    }
    assert overlay["rpc_authorized"] is False


def test_completion_overlay_rejects_partial_retry_root():
    targets = [_target("trace-1"), _target("trace-2")]
    source = _source("a", [_complete(targets[0], "a")])
    union = build_complete_source_union([source])
    retry_payload = build_retry_targets_from_verified_sources(
        original_targets=targets,
        original_targets_file_sha256="f" * 64,
        original_targets_sha256="e" * 64,
        activation_verification_file_sha256="d" * 64,
        activation_verification_sha256="c" * 64,
        spec_approval_record_sha256="b" * 64,
        sources=[source],
        union=union,
    )
    with pytest.raises(ControlTraceRetryOverlayError, match="retry_root_not_complete"):
        build_completion_overlay_from_verified(
            original_targets=targets,
            source_union=union,
            retry_source=_source("retry", [_complete(targets[1], "retry")]),
            retry_targets_payload=retry_payload,
            retry_targets_file_sha256="9" * 64,
            retry_targets_verification_sha256="8" * 64,
        )
