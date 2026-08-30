from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from chronosaudit_stage2.public_acquisition.control_base_state_retry_merge import (
    merge_base_state_retry_results,
)
from chronosaudit_stage2.public_acquisition.control_cutoff_state_acquisition import (
    CHECKPOINT_NAMESPACE,
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _batch(root: Path, rows: list[dict[str, object]], status: str) -> Path:
    root.mkdir()
    results = {
        "schema_version": "stage2_control_cutoff_state_results.v1",
        "target_count": len(rows),
        "processed_target_count": len(rows),
        "completed_target_count": sum(row["disposition"] == "complete" for row in rows),
        "dispositions": {},
        "targets": rows,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    results["results_sha256"] = _sha(results)
    results_path = root / "results.json"
    results_path.write_text(_canonical(results) + "\n", encoding="utf-8")
    ledger_path = root / "events.jsonl"
    ledger_path.write_text("{}\n", encoding="utf-8")
    checkpoint = {
        "schema_version": "stage2_control_cutoff_state_acquisition_checkpoint.v1",
        "status": status,
        "target_count": len(rows),
        "completed_target_count": results["completed_target_count"],
        "normalized_results_path": results_path.name,
        "normalized_results_sha256": hashlib.sha256(results_path.read_bytes()).hexdigest(),
        "event_ledger_path": ledger_path.name,
        "event_ledger_sha256": hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    checkpoint["checkpoint_sha256"] = _sha(checkpoint)
    path = root / "checkpoint.json"
    path.write_text(_canonical(checkpoint) + "\n", encoding="utf-8")
    return path


def _sign(checkpoint: Path, key: Path) -> Path:
    payload = checkpoint.with_suffix(".payload")
    payload.write_text(checkpoint.read_text(encoding="utf-8"), encoding="utf-8")
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(key), "-n", CHECKPOINT_NAMESPACE, str(payload)],
        check=True,
        capture_output=True,
    )
    return Path(str(payload) + ".sig")


def test_signed_retry_merge_replaces_only_exact_failed_identity(tmp_path: Path):
    complete = {"target_id": "a", "disposition": "complete", "result_sha256": "1" * 64}
    failed = {"target_id": "b", "disposition": "runtime_code_provider_error"}
    repaired = {"target_id": "b", "disposition": "complete", "result_sha256": "2" * 64}
    original = _batch(tmp_path / "original", [complete, failed], "PARTIAL_NON_AUTHORIZING")
    retry = _batch(tmp_path / "retry", [repaired], "COMPLETE")
    key = tmp_path / "key"
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    principal = "local-test"
    allowed = tmp_path / "allowed"
    allowed.write_text(f"{principal} {key.with_suffix('.pub').read_text().strip()}\n", encoding="utf-8")
    retry_targets = tmp_path / "retry-targets.json"
    retry_targets.write_text(_canonical({"targets": [{"target_id": "b"}]}) + "\n", encoding="utf-8")
    output = tmp_path / "merged.json"
    merged = merge_base_state_retry_results(
        original_checkpoint_path=original,
        original_signature_path=_sign(original, key),
        retry_checkpoint_path=retry,
        retry_signature_path=_sign(retry, key),
        retry_targets_path=retry_targets,
        allowed_signers_path=allowed,
        expected_principal=principal,
        output_path=output,
    )
    assert merged["completed_target_count"] == 2
    assert merged["dispositions"] == {"complete": 2}
    assert [row["result_sha256"] for row in merged["targets"]] == ["1" * 64, "2" * 64]
