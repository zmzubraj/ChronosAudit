from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from chronosaudit_stage2.public_acquisition.historical_snapshot_revision_run import (
    assemble_historical_snapshot_revision,
    canonical_revision_case_id,
    derive_revised_inputs,
)


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_derive_revised_inputs_rekeys_replacements_and_preserves_417(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    finalization = root / "raw/cohort_finalizations/2026-08-11/defihacklabs-temporal-replacements-final-v1"
    queue_path, temporal_path, provenance_path = derive_revised_inputs(
        finalization,
        output_root=tmp_path,
    )

    queue_rows = _read_rows(queue_path)
    temporal_rows = _read_rows(temporal_path)
    assert len(queue_rows) == len(temporal_rows) == 417
    assert len({row["case_id"] for row in temporal_rows}) == 417
    replacements = [row for row in temporal_rows if row["population_role"] == "replacement"]
    assert len(replacements) == 57
    assert all(row["candidate_id"].startswith("ca2r-") for row in replacements)
    assert all(row["case_id"].startswith("ca2-") for row in replacements)
    assert all(
        row["case_id"]
        == canonical_revision_case_id(
            row["case_name"], row["chain"], row["target_contract_address"], int(row["fork_block_number"])
        )
        for row in temporal_rows
    )
    assert provenance_path.is_file()


def test_derive_revised_inputs_rejects_nonempty_output(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    finalization = root / "raw/cohort_finalizations/2026-08-11/defihacklabs-temporal-replacements-final-v1"
    (tmp_path / "queue.csv").write_text("occupied", encoding="utf-8")
    with pytest.raises(ValueError, match="revision_input_output_occupied"):
        derive_revised_inputs(finalization, output_root=tmp_path)


@pytest.mark.parametrize("leaf", [False, True])
def test_derive_revised_inputs_rejects_symlinked_output_path(tmp_path: Path, leaf: bool) -> None:
    root = Path(__file__).resolve().parents[1]
    finalization = root / "raw/cohort_finalizations/2026-08-11/defihacklabs-temporal-replacements-final-v1"
    real = tmp_path / "real"
    real.mkdir()
    if leaf:
        output = tmp_path / "output"
        output.symlink_to(real, target_is_directory=True)
    else:
        ancestor = tmp_path / "alias"
        ancestor.symlink_to(real, target_is_directory=True)
        output = ancestor / "output"
    with pytest.raises(ValueError, match="revision_input_output_parent_invalid"):
        derive_revised_inputs(finalization, output_root=output)


def test_derive_revised_inputs_preserves_exact_source_bindings(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    finalization = root / "raw/cohort_finalizations/2026-08-11/defihacklabs-temporal-replacements-final-v1"
    bindings = {
        "parent_run_manifest": {"logical_id": "parent-run/run_manifest.json", "sha256": "a" * 64},
        "candidate_verification_inputs": {"logical_id": "candidate-report/verification_inputs.json", "sha256": "b" * 64},
    }
    _, _, provenance_path = derive_revised_inputs(
        finalization,
        output_root=tmp_path,
        source_bindings=bindings,
    )
    payload = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert payload["source_bindings"] == bindings
    assert "/Users/" not in json.dumps(payload["source_bindings"])


def _assembly_paths(root: Path) -> dict[str, Path]:
    return {
        "parent_run_root": root / "raw/historical_snapshots/2026-08-09/historical-snapshots-417-full-20260809",
        "parent_report_root": root / "reports/historical-snapshots-417-full-20260809-verification",
        "candidate_run_root": root / "raw/candidate_archive_qualification/2026-08-10/defihacklabs-temporal-replacements-v4-authoritative",
        "candidate_report_root": root / "reports/defihacklabs-temporal-replacements-v4-verification",
        "finalization_root": root / "raw/cohort_finalizations/2026-08-11/defihacklabs-temporal-replacements-final-v1",
    }


def test_assembly_rejects_forged_parent_report_before_output(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    paths = _assembly_paths(root)
    forged = tmp_path / "parent-report"
    shutil.copytree(paths["parent_report_root"], forged)
    report_path = forged / "historical_snapshot_verification_report.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["observed"] = 361
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    paths["parent_report_root"] = forged
    with pytest.raises(ValueError, match="parent_report_hash_invalid"):
        assemble_historical_snapshot_revision(**paths, output_dir=tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_assembly_rejects_tampered_candidate_verification_package(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    paths = _assembly_paths(root)
    forged = tmp_path / "candidate-report"
    shutil.copytree(paths["candidate_report_root"], forged)
    inputs = forged / "verification_inputs.json"
    inputs.write_text(inputs.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    paths["candidate_report_root"] = forged
    with pytest.raises(ValueError, match="candidate_checksum_mismatch:verification_inputs.json"):
        assemble_historical_snapshot_revision(**paths, output_dir=tmp_path / "out")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("leaf", [False, True])
def test_assembly_rejects_symlinked_output_path(tmp_path: Path, leaf: bool) -> None:
    root = Path(__file__).resolve().parents[1]
    paths = _assembly_paths(root)
    real = tmp_path / "real"
    real.mkdir()
    if leaf:
        output = tmp_path / "out"
        output.symlink_to(real, target_is_directory=True)
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(real, target_is_directory=True)
        output = alias / "out"
    with pytest.raises(ValueError, match="revision_output_parent_invalid"):
        assemble_historical_snapshot_revision(**paths, output_dir=output)


def test_assembly_cli_sanitizes_failures(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            str(root / "assemble_historical_snapshot_revision.py"),
            "--parent-run-root",
            str(tmp_path / "private-parent-path"),
            "--parent-report-root",
            str(tmp_path / "private-report-path"),
            "--candidate-run-root",
            str(tmp_path / "private-candidate-path"),
            "--candidate-report-root",
            str(tmp_path / "private-candidate-report-path"),
            "--finalization-root",
            str(tmp_path / "private-finalization-path"),
            "--output-dir",
            str(tmp_path / "out"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert json.loads(result.stderr) == {
        "code": "assembly_failed",
        "error": "historical_snapshot_revision_assembly_failed",
    }
    assert "Traceback" not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_assembly_freezes_exact_portable_source_identities(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "historical-snapshots-revision-e2e"
    assemble_historical_snapshot_revision(**_assembly_paths(root), output_dir=output)
    payload = json.loads((output / "frozen_inputs/incident_input.json").read_text(encoding="utf-8"))
    bindings = payload["source_bindings"]
    assert bindings["parent_run_manifest"]["logical_id"] == (
        "chronosaudit://historical-snapshot-run/"
        "historical-snapshots-417-full-20260809/run_manifest.json"
    )
    assert bindings["candidate_verification_inputs"]["logical_id"] == (
        "chronosaudit://candidate-archive-verification/"
        "defihacklabs-temporal-replacements-v4-authoritative/verification_inputs.json"
    )
    assert all(str(value["logical_id"]).startswith("chronosaudit://") for value in bindings.values())
    assert "/Users/" not in json.dumps(bindings)


def test_public_plan_can_freeze_a_revised_queue_and_positive_population(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    historical = root / "raw/historical_snapshots/2026-08-11/historical-snapshots-417-revised-v2/frozen_inputs"
    result = subprocess.run(
        [
            sys.executable,
            str(root / "run_public_evidence_acquisition.py"),
            "plan",
            "--output-root",
            str(tmp_path),
            "--revision",
            "revision-test",
            "--run-id",
            "public-acquisition-revision-test",
            "--queue-source-path",
            str(historical / "queue.csv"),
            "--positive-cases-path",
            str(historical / "temporal.csv"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["queue_rows"] == 417
    report = tmp_path / "reports/public_acquisition/revision-test/public-acquisition-revision-test/case_queue_manifest.json"
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["source_snapshot_sha256"] == hashlib.sha256((historical / "queue.csv").read_bytes()).hexdigest()
    assert payload["positive_snapshot_sha256"] == hashlib.sha256((historical / "temporal.csv").read_bytes()).hexdigest()
