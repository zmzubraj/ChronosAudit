from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

import pytest

import chronosaudit_stage2.public_acquisition.historical_snapshot_run as case_execution_module
from chronosaudit_stage2.public_acquisition.historical_snapshot_run import execute_snapshot_case
from chronosaudit_stage2.public_acquisition.strict_snapshot import InsufficientIncidentLeadTimeError
from test_public_acquisition_strict_snapshot import (
    _case as _strict_case,
    _identity_artifact,
    _policy as _strict_policy,
    _rehash_snapshot,
    _strict_snapshot,
)


def _case() -> dict[str, object]:
    return {
        "case_id": "ca2-case-exec",
        "case_name": "Case Exec",
        "chain": "ethereum",
        "address": "0x1111111111111111111111111111111111111111",
        "incident_block": 42,
        "input_row_sha256": "1" * 64,
    }


def _policy() -> dict[str, object]:
    return {
        "cutoff_policy": {
            "rule": "deployment_plus_24h",
            "primary_landmark_hours": 24,
            "minimum_incident_lead_hours": 1.0,
        }
    }


def _strict_execution_case() -> dict[str, object]:
    return {
        **_strict_case(),
        "input_row_sha256": "2" * 64,
    }


def _strict_execution_policy() -> dict[str, object]:
    return {
        **_strict_policy(),
        "provider_identity": _identity_artifact(),
    }


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _sealed_transition(payload: dict[str, object]) -> dict[str, object]:
    inner = dict(payload)
    inner.pop("proof_sha256_without_self_hash", None)
    inner.pop("proof_sha256", None)
    payload["proof_sha256_without_self_hash"] = _sha256_json(inner)
    outer = dict(inner)
    outer["proof_sha256_without_self_hash"] = payload["proof_sha256_without_self_hash"]
    payload["proof_sha256"] = _sha256_json(outer)
    return payload


def _strict_snapshot_for_case(receipt_root: Path, case: dict[str, object]) -> dict[str, object]:
    snapshot = _strict_snapshot(receipt_root)
    snapshot["case_id"] = str(case["case_id"])
    snapshot["case_name"] = str(case["case_name"])
    snapshot["chain"] = str(case["chain"])
    snapshot["address"] = str(case["address"]).lower()
    snapshot["incident_block"] = int(case["incident_block"])
    snapshot["case_input"] = dict(case)
    snapshot["case_input_sha256"] = _sha256_json(case)
    return _rehash_snapshot(snapshot)


def _reseal_envelope(envelope: dict[str, object]) -> dict[str, object]:
    return case_execution_module._seal_snapshot_case_envelope(envelope)


def test_execute_snapshot_case_persists_verified_envelope(tmp_path: Path) -> None:
    case = _strict_execution_case()
    calls: list[tuple[str, object]] = []
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })
    strict_snapshot = _strict_snapshot_for_case(tmp_path / "receipts", case)

    def transition_discoverer(case_arg, providers_arg, receipt_root_arg):
        calls.append(("transition", dict(case_arg)))
        assert providers_arg == ["provider-a", "provider-b"]
        assert Path(receipt_root_arg) == tmp_path / "receipts"
        return dict(transition)

    def snapshot_acquirer(case_arg, *, providers, policy, receipt_root, cached_artifact=None):
        calls.append(("strict", dict(case_arg)))
        assert case_arg["deployment_block"] == 100
        assert providers == ["provider-a", "provider-b"]
        assert policy == _strict_execution_policy()
        assert Path(receipt_root) == tmp_path / "receipts"
        assert cached_artifact is None
        return dict(strict_snapshot)

    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=_strict_execution_policy(),
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=transition_discoverer,
        snapshot_acquirer=snapshot_acquirer,
    )

    case_path = tmp_path / "cases" / f"{case['case_id']}.json"
    persisted = json.loads(case_path.read_text(encoding="utf-8"))

    assert [name for name, _payload in calls] == ["transition", "strict"]
    assert result["status"] == "VERIFIED"
    assert result["strict_snapshot_closed"] is True
    assert result["case_path"] == "ca2-testcase0000000001.json"
    assert persisted["status"] == "VERIFIED"
    assert persisted["strict_snapshot"]["artifact_sha256"] == strict_snapshot["artifact_sha256"]
    assert persisted["transition_proof"]["candidate_block"] == 100


def test_execute_snapshot_case_invalid_strict_artifact_fails_closed(tmp_path: Path) -> None:
    case = _strict_execution_case()
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 12,
    })

    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=_strict_execution_policy(),
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda *_args, **_kwargs: {
            "case_id": str(case["case_id"]),
            "strict_snapshot_closed": True,
            "artifact_sha256_without_self_hash": "c" * 64,
            "artifact_sha256": "d" * 64,
            "blockers": [],
            "status": "VERIFIED",
            "blocked_reason": None,
        },
    )

    assert result["status"] == "PARTIAL"
    assert result["strict_snapshot_closed"] is False
    assert "schema_validation_failed" in result["blockers"]


def test_execute_snapshot_case_fails_closed_for_partial_transition(tmp_path: Path) -> None:
    strict_called = False

    def transition_discoverer(_case_arg, _providers_arg, _receipt_root_arg):
        return _sealed_transition({
            "status": "PARTIAL",
            "blockers": ["provider_disagreement"],
            "candidate_block": 12,
        })

    def snapshot_acquirer(**_kwargs):
        nonlocal strict_called
        strict_called = True
        raise AssertionError("strict snapshot acquisition should not run")

    result = execute_snapshot_case(
        _case(),
        providers=["provider-a", "provider-b"],
        policy=_strict_execution_policy(),
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=transition_discoverer,
        snapshot_acquirer=snapshot_acquirer,
    )

    persisted = json.loads((tmp_path / "cases" / "ca2-case-exec.json").read_text(encoding="utf-8"))

    assert strict_called is False
    assert result["status"] == "PARTIAL"
    assert result["strict_snapshot_closed"] is False
    assert "provider_disagreement" in result["blockers"]
    assert persisted["strict_snapshot_closed"] is False


def test_execute_snapshot_case_retries_valid_partial_only_when_explicit(tmp_path: Path) -> None:
    case = _strict_execution_case()
    policy = _strict_execution_policy()
    partial_transition = _sealed_transition(
        {"status": "PARTIAL", "blockers": ["provider_disagreement"], "candidate_block": 100}
    )
    verified_transition = _sealed_transition(
        {"status": "VERIFIED", "blockers": [], "candidate_block": 100}
    )

    first = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: dict(partial_transition),
    )
    assert first["status"] == "PARTIAL"

    retried = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: dict(verified_transition),
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(
            tmp_path / "receipts", case
        ),
        retry_partial=True,
    )

    assert retried["status"] == "VERIFIED"
    assert retried["strict_snapshot_closed"] is True
    assert retried["quarantined"] is True
    assert retried["quarantine_reason"] == "retry_partial"


def test_execute_snapshot_case_reuses_valid_envelope_without_dependency_calls(tmp_path: Path) -> None:
    case = _strict_execution_case()
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })
    policy = _strict_execution_policy()

    first = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
    )

    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: (_ for _ in ()).throw(AssertionError("resume should skip transition discovery")),
        snapshot_acquirer=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("resume should skip strict acquisition")),
    )

    assert result["status"] == "VERIFIED"
    assert result["strict_snapshot_closed"] is True
    assert result["resumed"] is True
    assert result.get("quarantined") is not True
    assert case_execution_module._validate_snapshot_case_envelope_hashes(result) is True


def test_execute_snapshot_case_quarantines_policy_mismatch_and_retries(tmp_path: Path) -> None:
    case = _strict_execution_case()
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })
    initial_policy = _strict_execution_policy()

    execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=initial_policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
    )

    retry_count = 0

    def retry_transition(*_args):
        nonlocal retry_count
        retry_count += 1
        return dict(transition)

    updated_policy = {
        **initial_policy,
        "cutoff_policy": {
            **initial_policy["cutoff_policy"],
            "primary_landmark_hours": 12,
        },
    }
    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=updated_policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=retry_transition,
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
    )

    quarantine_dir = tmp_path / "cases" / "quarantine" / str(case["case_id"])

    assert retry_count == 1
    assert result["status"] == "VERIFIED"
    assert result["quarantined"] is True
    assert result["quarantine_reason"] == "policy_mismatch"
    assert sorted(path.name for path in quarantine_dir.iterdir())[-1].endswith(".json")


def test_execute_snapshot_case_reuses_valid_fail_closed_envelope_without_dependency_calls(tmp_path: Path) -> None:
    transition = _sealed_transition({
        "status": "PARTIAL",
        "blockers": ["provider_disagreement"],
        "candidate_block": 12,
    })

    execute_snapshot_case(
        _case(),
        providers=["provider-a", "provider-b"],
        policy=_policy(),
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("strict acquisition should not run")),
    )

    result = execute_snapshot_case(
        _case(),
        providers=["provider-a", "provider-b"],
        policy=_policy(),
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: (_ for _ in ()).throw(AssertionError("resume should skip transition discovery")),
        snapshot_acquirer=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("resume should skip strict acquisition")),
    )

    assert result["resumed"] is True
    assert result["status"] == "PARTIAL"
    assert result["strict_snapshot_closed"] is False
    assert "provider_disagreement" in result["blockers"]


def test_execute_snapshot_case_normalizes_nan_case_inputs_for_stable_resume(tmp_path: Path) -> None:
    case = _strict_execution_case()
    case.pop("deployment_block")
    case["prediction_cutoff_block"] = float("nan")
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })

    first = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=_strict_execution_policy(),
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda strict_case, **_kwargs: _strict_snapshot_for_case(
            tmp_path / "receipts",
            strict_case,
        ),
    )

    assert first["strict_snapshot_closed"] is True
    assert case_execution_module._candidate_closed(tmp_path, case, first) is True

    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=_strict_execution_policy(),
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: (_ for _ in ()).throw(AssertionError("resume should skip transition discovery")),
        snapshot_acquirer=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("resume should skip strict acquisition")),
    )

    assert result["resumed"] is True
    assert result["case_input"]["prediction_cutoff_block"] is None


def test_execute_snapshot_case_quarantines_invalid_partial_artifact_on_resume(tmp_path: Path) -> None:
    transition = _sealed_transition({
        "status": "PARTIAL",
        "blockers": ["provider_disagreement"],
        "candidate_block": 12,
    })
    case_root = tmp_path / "cases"
    case = _case()

    execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=_policy(),
        receipt_root=tmp_path / "receipts",
        case_root=case_root,
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("strict acquisition should not run")),
    )

    case_path = case_root / f"{case['case_id']}.json"
    envelope = json.loads(case_path.read_text(encoding="utf-8"))
    envelope["strict_snapshot"]["blocked_reason"] = "wrong_reason"
    envelope = _reseal_envelope(envelope)
    case_path.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")

    retried = {"count": 0}

    def retried_transition(*_args):
        retried["count"] += 1
        return dict(transition)

    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=_policy(),
        receipt_root=tmp_path / "receipts",
        case_root=case_root,
        transition_discoverer=retried_transition,
        snapshot_acquirer=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("strict acquisition should not run")),
    )

    assert retried["count"] == 1
    assert result["quarantined"] is True
    assert result["quarantine_reason"] == "partial_strict_artifact_invalid"


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ("corrupt_json", "corrupt_json"),
        ("case_mismatch", "case_mismatch"),
        ("self_hash_mismatch", "self_hash_mismatch"),
    ],
)
def test_execute_snapshot_case_quarantines_invalid_existing_envelopes(
    tmp_path: Path,
    mutation: str,
    expected_reason: str,
) -> None:
    case = _strict_execution_case()
    policy = _strict_execution_policy()
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })
    case_root = tmp_path / "cases"
    case_path = case_root / f"{case['case_id']}.json"

    execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=case_root,
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
    )

    if mutation == "corrupt_json":
        case_path.write_text("{", encoding="utf-8")
    else:
        envelope = json.loads(case_path.read_text(encoding="utf-8"))
        if mutation == "case_mismatch":
            envelope["case_input"] = {**envelope["case_input"], "case_id": "ca2-other"}
            envelope["case_input_sha256"] = _sha256_json(envelope["case_input"])
            envelope = _reseal_envelope(envelope)
        elif mutation == "self_hash_mismatch":
            envelope["status"] = "CORRUPTED"
        case_path.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")

    retried = {"count": 0}

    def retried_transition(*_args):
        retried["count"] += 1
        return dict(transition)

    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=case_root,
        transition_discoverer=retried_transition,
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
    )

    quarantine_dir = case_root / "quarantine" / str(case["case_id"])

    assert retried["count"] == 1
    assert result["quarantined"] is True
    assert result["quarantine_reason"] == expected_reason
    assert any(path.name.endswith(".json") for path in quarantine_dir.iterdir())


def test_execute_snapshot_case_quarantines_receipt_binding_tamper(tmp_path: Path) -> None:
    case = _strict_execution_case()
    policy = _strict_execution_policy()
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })
    case_root = tmp_path / "cases"

    execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=case_root,
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
    )

    receipt_path = next((tmp_path / "receipts").rglob("*.json"))
    receipt_path.write_text("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"tampered\"}", encoding="utf-8")

    retried = {"count": 0}

    def retried_transition(*_args):
        retried["count"] += 1
        return dict(transition)

    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=case_root,
        transition_discoverer=retried_transition,
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
    )

    assert retried["count"] == 1
    assert result["quarantined"] is True
    assert result["quarantine_reason"] == "receipt_binding_invalid"


@pytest.mark.parametrize(
    ("raiser", "expected_blocker"),
    [
        (lambda: RuntimeError("secret-token should never leak"), "transition_exception"),
        (lambda: ValueError("api-key should never leak"), "snapshot_acquisition_exception"),
        (
            lambda: InsufficientIncidentLeadTimeError("upper bound is before target"),
            "insufficient_incident_lead_time",
        ),
    ],
)
def test_execute_snapshot_case_sanitizes_exception_envelopes(
    tmp_path: Path,
    raiser,
    expected_blocker: str,
) -> None:
    case = _strict_execution_case()
    policy = _strict_execution_policy()
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })

    def transition_discoverer(*_args):
        if expected_blocker == "transition_exception":
            raise raiser()
        return dict(transition)

    def snapshot_acquirer(*_args, **_kwargs):
        if expected_blocker != "transition_exception":
            raise raiser()
        return _strict_snapshot_for_case(tmp_path / "receipts", case)

    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=transition_discoverer,
        snapshot_acquirer=snapshot_acquirer,
    )

    serialized = json.dumps(result, sort_keys=True)

    assert result["strict_snapshot_closed"] is False
    assert result["status"] == "PARTIAL"
    assert result["blockers"] == [expected_blocker]
    assert "secret-token" not in serialized
    assert "api-key" not in serialized


def test_execute_snapshot_case_interruption_before_replace_leaves_no_partial_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = _strict_execution_case()
    policy = _strict_execution_policy()
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })
    case_path = tmp_path / "cases" / f"{case['case_id']}.json"
    original_atomic_write_text = case_execution_module._atomic_write_text

    interrupted = {"value": False}

    def interrupted_atomic_write(path: Path, text: str) -> None:
        if not interrupted["value"]:
            interrupted["value"] = True
            raise RuntimeError("simulated interruption before replace")
        original_atomic_write_text(path, text)

    monkeypatch.setattr(case_execution_module, "_atomic_write_text", interrupted_atomic_write)

    with pytest.raises(RuntimeError, match="simulated interruption"):
        execute_snapshot_case(
            case,
            providers=["provider-a", "provider-b"],
            policy=policy,
            receipt_root=tmp_path / "receipts",
            case_root=tmp_path / "cases",
            transition_discoverer=lambda *_args: dict(transition),
            snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
        )

    assert not case_path.exists()

    monkeypatch.setattr(case_execution_module, "_atomic_write_text", original_atomic_write_text)
    resumed = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
    )

    assert resumed["status"] == "VERIFIED"
    assert case_path.exists()


def test_execute_snapshot_case_concurrent_duplicate_calls_execute_once_even_past_stale_threshold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _strict_execution_case()
    policy = _strict_execution_policy()
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })
    monkeypatch.setattr(case_execution_module, "_CASE_CLAIM_STALE_AFTER_SECONDS", 0.05)
    monkeypatch.setattr(case_execution_module, "_CASE_CLAIM_HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setattr(case_execution_module, "_CASE_CLAIM_POLL_SECONDS", 0.005)
    started = threading.Event()
    release = threading.Event()
    calls = {"count": 0}
    results: list[dict[str, object]] = []

    def transition_discoverer(*_args):
        return dict(transition)

    def snapshot_acquirer(*_args, **_kwargs):
        calls["count"] += 1
        started.set()
        release.wait(timeout=2)
        return _strict_snapshot_for_case(tmp_path / "receipts", case)

    def runner() -> None:
        results.append(
            execute_snapshot_case(
                case,
                providers=["provider-a", "provider-b"],
                policy=policy,
                receipt_root=tmp_path / "receipts",
                case_root=tmp_path / "cases",
                transition_discoverer=transition_discoverer,
                snapshot_acquirer=snapshot_acquirer,
            )
        )

    first = threading.Thread(target=runner)
    second = threading.Thread(target=runner)
    first.start()
    second.start()

    assert started.wait(timeout=1)
    time.sleep(0.15)
    release.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert calls["count"] == 1
    assert len(results) == 2
    assert all(result["status"] == "VERIFIED" for result in results)


def test_execute_snapshot_case_reclaims_stale_claim_file(tmp_path: Path) -> None:
    case = _strict_execution_case()
    policy = _strict_execution_policy()
    transition = _sealed_transition({
        "status": "VERIFIED",
        "blockers": [],
        "candidate_block": 100,
    })
    claim_path = tmp_path / "cases" / ".claims" / f"{case['case_id']}.lock"
    claim_path.parent.mkdir(parents=True, exist_ok=True)
    claim_path.write_text("{\"token\":\"stale\",\"created_at_utc\":\"2026-08-08T12:00:00Z\"}", encoding="utf-8")
    os.utime(claim_path, (time.time() - 10, time.time() - 10))

    result = execute_snapshot_case(
        case,
        providers=["provider-a", "provider-b"],
        policy=policy,
        receipt_root=tmp_path / "receipts",
        case_root=tmp_path / "cases",
        transition_discoverer=lambda *_args: dict(transition),
        snapshot_acquirer=lambda *_args, **_kwargs: _strict_snapshot_for_case(tmp_path / "receipts", case),
    )

    assert result["status"] == "VERIFIED"
    assert claim_path.exists() is False
