from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pandas as pd
import pytest

from chronosaudit_stage2.public_acquisition.control_qualification_evidence import (
    CONTROL_QUALIFICATION_GATES,
    ControlQualificationEvidenceError,
    verify_control_qualification_evidence_batch,
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _candidate() -> dict[str, object]:
    return {
        "case_name": "case-1",
        "chain": "ethereum",
        "contract_address": "0x" + "aa" * 20,
        "candidate_status": "CANDIDATE_CONTROL",
        "candidate_row_valid": True,
        "control_row_sha256": "c" * 64,
    }


def _batch(tmp_path: Path) -> tuple[pd.DataFrame, pd.DataFrame, Path]:
    root = tmp_path / "evidence"
    root.mkdir()
    candidate = _candidate()
    rows: list[dict[str, object]] = []
    for gate in CONTROL_QUALIFICATION_GATES:
        source_relative = Path("case-1") / "sources" / f"{gate}.txt"
        source_path = root / source_relative
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(f"direct {gate} source evidence", encoding="utf-8")
        evidence = {
            "schema_version": "chronosaudit.control_check_evidence.v1",
            "case_name": candidate["case_name"],
            "chain": candidate["chain"],
            "contract_address": candidate["contract_address"],
            "candidate_control_row_sha256": candidate["control_row_sha256"],
            "gate": gate,
            "result": "PASS",
            "decision_rule": f"frozen {gate} rule satisfied",
            "observations": [f"direct {gate} evidence reviewed"],
            "source_artifact_path": source_relative.as_posix(),
            "source_artifact_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        }
        relative = Path("case-1") / f"{gate}.json"
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        row = {
            "schema_version": "chronosaudit.control_qualification_check.v1",
            "case_name": candidate["case_name"],
            "chain": candidate["chain"],
            "contract_address": candidate["contract_address"],
            "candidate_control_row_sha256": candidate["control_row_sha256"],
            "gate": gate,
            "check_status": "PASS",
            "evidence_path": relative.as_posix(),
            "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "reviewer_identity": f"reviewer-{gate}",
            "reviewer_owner": f"owner-{gate}",
            "reviewer_kind": (
                "HUMAN"
                if gate in {"maturity", "censoring", "mechanism_separation"}
                else "MECHANICAL"
            ),
            "reviewer_conflict_clear": True,
            "reviewer_confidence": "high",
            "reviewed_at_utc": "2026-08-20T00:00:00Z",
        }
        row["evidence_record_sha256"] = _canonical_sha256(row)
        rows.append(row)
    return pd.DataFrame([candidate]), pd.DataFrame(rows), root


def test_verifies_exact_eight_gate_batch_but_remains_non_authorizing(
    tmp_path: Path,
) -> None:
    candidates, checks, root = _batch(tmp_path)
    report = verify_control_qualification_evidence_batch(
        candidate_rows=candidates,
        check_rows=checks,
        evidence_root=root,
    )
    assert report["decision"] == "QUALIFICATION_EVIDENCE_VERIFIED_NON_AUTHORIZING"
    assert report["candidate_rows_verified"] == 1
    assert report["check_rows_verified"] == 8
    assert report["gate_counts"] == {gate: 1 for gate in CONTROL_QUALIFICATION_GATES}
    assert report["qualification_authorized"] is False
    assert report["counter_authority"] is False
    assert report["stage_promotion_authorized"] is False


def test_rejects_missing_gate(tmp_path: Path) -> None:
    candidates, checks, root = _batch(tmp_path)
    checks = checks[checks["gate"] != "proxy"].copy()
    with pytest.raises(ControlQualificationEvidenceError, match="gate_set_invalid"):
        verify_control_qualification_evidence_batch(
            candidate_rows=candidates, check_rows=checks, evidence_root=root
        )


def test_rejects_tampered_evidence_file(tmp_path: Path) -> None:
    candidates, checks, root = _batch(tmp_path)
    (root / "case-1" / "temporal.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ControlQualificationEvidenceError, match="evidence_sha256_mismatch"):
        verify_control_qualification_evidence_batch(
            candidate_rows=candidates, check_rows=checks, evidence_root=root
        )


def test_rejects_mechanical_reviewer_for_outcome_dependent_gate(tmp_path: Path) -> None:
    candidates, checks, root = _batch(tmp_path)
    index = checks.index[checks["gate"] == "mechanism_separation"][0]
    checks.loc[index, "reviewer_kind"] = "MECHANICAL"
    unsigned = checks.loc[index].to_dict()
    unsigned.pop("evidence_record_sha256")
    checks.loc[index, "evidence_record_sha256"] = _canonical_sha256(unsigned)
    with pytest.raises(
        ControlQualificationEvidenceError, match="accountable_human_reviewer_required"
    ):
        verify_control_qualification_evidence_batch(
            candidate_rows=candidates, check_rows=checks, evidence_root=root
        )


def test_rejects_semantically_mismatched_evidence(tmp_path: Path) -> None:
    candidates, checks, root = _batch(tmp_path)
    path = root / "case-1" / "protocol.json"
    evidence = json.loads(path.read_text(encoding="utf-8"))
    evidence["gate"] = "proxy"
    path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    index = checks.index[checks["gate"] == "protocol"][0]
    checks.loc[index, "evidence_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    unsigned = checks.loc[index].to_dict()
    unsigned.pop("evidence_record_sha256")
    checks.loc[index, "evidence_record_sha256"] = _canonical_sha256(unsigned)
    with pytest.raises(ControlQualificationEvidenceError, match="evidence_binding_mismatch"):
        verify_control_qualification_evidence_batch(
            candidate_rows=candidates, check_rows=checks, evidence_root=root
        )


def test_cli_writes_non_authorizing_report_atomically(tmp_path: Path) -> None:
    candidates, checks, root = _batch(tmp_path)
    candidate_path = tmp_path / "candidates.csv"
    check_path = tmp_path / "checks.csv"
    report_path = tmp_path / "report.json"
    candidates.to_csv(candidate_path, index=False)
    checks.to_csv(check_path, index=False)
    script = Path(__file__).resolve().parents[1] / "verify_stage2_control_qualification_evidence.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--candidates",
            str(candidate_path),
            "--checks",
            str(check_path),
            "--evidence-root",
            str(root),
            "--output-report",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["decision"] == "QUALIFICATION_EVIDENCE_VERIFIED_NON_AUTHORIZING"
    assert report["counter_authority"] is False
