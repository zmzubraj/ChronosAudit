from __future__ import annotations

import csv
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/chronosaudit_stage2/public_acquisition/replacement_finalization.py"
CLI_PATH = ROOT / "finalize_historical_snapshot_replacements.py"
PARENT_RUN_ROOT = (
    ROOT
    / "raw/historical_snapshots/2026-08-09/historical-snapshots-417-full-20260809"
)
PARENT_REPORT_ROOT = ROOT / "reports/historical-snapshots-417-full-20260809-verification"
REVISION_ROOT = ROOT / "raw/cohort_revisions/2026-08-10/defihacklabs-temporal-replacements-v1"
CANDIDATE_RUN_ROOT = (
    ROOT
    / "raw/candidate_archive_qualification/2026-08-10/defihacklabs-temporal-replacements-v4-authoritative"
)
CANDIDATE_REPORT_ROOT = ROOT / "reports/defihacklabs-temporal-replacements-v4-verification"
EXPECTED_QUOTAS = {"base": 3, "bsc": 38, "ethereum": 16}
EXPECTED_SELECTED_BY_CHAIN = {
    "base": [
        "ca2r-8fe204813ba2bc5d94e9",
        "ca2r-d88870d32e6a33a7cd53",
        "ca2r-a888af28bf0d219d083d",
    ],
    "bsc": [
        "ca2r-88058b64a3023c297a5f",
        "ca2r-ae46a532dce783daeeab",
        "ca2r-13900db60de0d818c3a8",
        "ca2r-26dba834d99618c7908c",
        "ca2r-df644d704ca7d12c2f8f",
        "ca2r-e22bc2bae94b6b863002",
        "ca2r-96e8a384c0d4cd3a86c8",
        "ca2r-2e49a393c3be739e3708",
        "ca2r-04d28cc672bd269a3cf0",
        "ca2r-5c2f397092821899808b",
        "ca2r-8648cd24a3c3d24eeba3",
        "ca2r-8426b54765c9d7889888",
        "ca2r-9c92a7be5fd1d6be88ab",
        "ca2r-fa3009b447f82845b037",
        "ca2r-b974d5d0842cce12a330",
        "ca2r-51fea100b454e9f084dd",
        "ca2r-78aa47e4d635df3fecbd",
        "ca2r-51ce7cb9c10cf1ea2cc8",
        "ca2r-355cc8136e6146456061",
        "ca2r-6698a749069349aab0a8",
        "ca2r-d114caf3ade0518b55c5",
        "ca2r-e9f556db91d7398a8565",
        "ca2r-90eb561aa424bfd69e9c",
        "ca2r-30e61eedd2e8aba1ccf7",
        "ca2r-7b25633e7957bf6c7f6d",
        "ca2r-6619e8b9582785ce3f40",
        "ca2r-2d7002c3d03e4977a6c2",
        "ca2r-69e5fdd533acbfbc9416",
        "ca2r-afc2255d4280cce6776a",
        "ca2r-b4e0d64ff67197d3308f",
        "ca2r-ae96ab39f6032c3c3d8c",
        "ca2r-a7eede03122760827180",
        "ca2r-c9acdaf52fc98f4159f7",
        "ca2r-9022409faa3cf5abff6e",
        "ca2r-e31701db07607d92a7db",
        "ca2r-0a3059d0a1060001da97",
        "ca2r-abdf718c43ec37a0dab9",
        "ca2r-f5416837282fcac56f59",
    ],
    "ethereum": [
        "ca2r-c5000b611e63dc8b50ad",
        "ca2r-ba5125556e042805b88d",
        "ca2r-7d8d3b48599e130a52b1",
        "ca2r-41177cdba4ea41d36160",
        "ca2r-71a7b10a92a8672d68bf",
        "ca2r-b6d111fdecac176c80c6",
        "ca2r-84069bad8e1b044be32b",
        "ca2r-8b1891d813e93e9a4d43",
        "ca2r-fe3bfa9fe63a233f5747",
        "ca2r-42c358b27a61c5198e9b",
        "ca2r-b2a222e969681c109367",
        "ca2r-5a2776d03ace766cf975",
        "ca2r-8b568c5a45a75d104376",
        "ca2r-971b334afcda0571a76b",
        "ca2r-dd7f35603441e3e88cbe",
        "ca2r-6e609f3614c863b93d77",
    ],
}


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _module():
    return _load_module("replacement_finalization_module", MODULE_PATH)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv_rows(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _rewrite_sha256sums(root: Path, names: list[str] | None = None) -> None:
    if names is None:
        names = sorted(path.name for path in root.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    lines = []
    for name in names:
        path = root / name
        lines.append(f"{_module()._sha256_file(path)}  {name}")
    (root / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sync_candidate_verifier_revision_bindings(candidate_run: Path, candidate_report: Path, revision: Path) -> None:
    revision_hashes = {}
    for name in (
        "SHA256SUMS.txt",
        "provenance.json",
        "replacement_slots.csv",
        "revision_plan.json",
        "screened_candidates.csv",
        "screening_log.json",
        "slot_candidate_order.csv",
    ):
        revision_hashes[name] = _module()._sha256_file(revision / name)

    manifest_path = candidate_run / "run_manifest.json"
    manifest = _read_json(manifest_path)
    manifest["revision_input_hashes"] = revision_hashes
    manifest["binding_sha256"] = _module()._sha256_json(
        {key: value for key, value in manifest.items() if key != "binding_sha256"}
    )
    _write_json(manifest_path, manifest)
    run_manifest_sha = _module()._sha256_file(manifest_path)
    qualification_result_sha = _module()._sha256_file(candidate_run / "qualification_result.json")

    report_path = candidate_report / "candidate_archive_verification_report.json"
    report = _read_json(report_path)
    report["authoritative_input_hashes"] = {
        "run_manifest_sha256": run_manifest_sha,
        "qualification_result_sha256": qualification_result_sha,
        "run_binding_sha256": manifest["binding_sha256"],
        "revision_input_hashes": revision_hashes,
    }
    _write_json(report_path, _rehash_report(report))

    inputs_path = candidate_report / "verification_inputs.json"
    _write_json(
        inputs_path,
        {
            "schema_version": "candidate_archive_verification_inputs.v1",
            "run_manifest_sha256": run_manifest_sha,
            "qualification_result_sha256": qualification_result_sha,
            "run_binding_sha256": manifest["binding_sha256"],
            "revision_input_hashes": revision_hashes,
        },
    )
    _rewrite_sha256sums(
        candidate_report,
        [
            "candidate_archive_verification_report.json",
            "candidate_archive_verified_projection.csv",
            "verification_inputs.json",
        ],
    )


def _rehash_report(payload: dict[str, Any]) -> dict[str, Any]:
    body = {key: value for key, value in payload.items() if key != "report_sha256"}
    payload["report_sha256"] = _module()._sha256_json(body)
    return payload


def _fixture_roots(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    parent_run = tmp_path / "parent-run"
    parent_report = tmp_path / "parent-report"
    revision = tmp_path / "revision"
    candidate_run = tmp_path / "candidate-run"
    candidate_report = tmp_path / "candidate-report"
    shutil.copytree(PARENT_RUN_ROOT, parent_run)
    shutil.copytree(PARENT_REPORT_ROOT, parent_report)
    shutil.copytree(REVISION_ROOT, revision)
    shutil.copytree(CANDIDATE_RUN_ROOT, candidate_run)
    shutil.copytree(CANDIDATE_REPORT_ROOT, candidate_report)
    return parent_run, parent_report, revision, candidate_run, candidate_report


def _finalize_to_tmp(
    tmp_path: Path,
    *,
    parent_run_root: Path,
    parent_report_root: Path,
    revision_root: Path,
    candidate_run_root: Path,
    candidate_report_root: Path,
    output_name: str = "finalized",
) -> dict[str, Any]:
    return _module().finalize_historical_snapshot_replacements(
        parent_run_root=parent_run_root,
        parent_report_root=parent_report_root,
        revision_root=revision_root,
        candidate_run_root=candidate_run_root,
        candidate_report_root=candidate_report_root,
        output_dir=tmp_path / output_name,
    )


def test_finalize_replacements_builds_exact_authoritative_mapping(tmp_path: Path) -> None:
    output_dir = tmp_path / "finalized"

    result = _module().finalize_historical_snapshot_replacements(
        parent_run_root=PARENT_RUN_ROOT,
        parent_report_root=PARENT_REPORT_ROOT,
        revision_root=REVISION_ROOT,
        candidate_run_root=CANDIDATE_RUN_ROOT,
        candidate_report_root=CANDIDATE_REPORT_ROOT,
        output_dir=output_dir,
    )

    mapping_rows = _read_csv_rows(output_dir / "replacement_mapping.csv")
    revised_rows = _read_csv_rows(output_dir / "revised_population.csv")
    manifest = _read_json(output_dir / "finalization_manifest.json")

    assert result == manifest
    assert len(mapping_rows) == 57
    assert len(revised_rows) == 417
    assert manifest["slot_quotas"] == EXPECTED_QUOTAS
    assert manifest["selected_candidate_ids_by_chain"] == EXPECTED_SELECTED_BY_CHAIN


def test_finalize_replacements_rejects_parent_counter_authority_false(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    report_path = parent_report / "historical_snapshot_verification_report.json"
    report = _read_json(report_path)
    report["counter_authority"] = False
    _write_json(report_path, _rehash_report(report))

    with pytest.raises(ValueError, match="parent_counter_authority_invalid"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
        )
    assert not (tmp_path / "finalized").exists()


def test_finalize_replacements_rejects_candidate_projection_row_count_drift(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    projection_path = candidate_report / "candidate_archive_verified_projection.csv"
    rows = _read_csv_rows(projection_path)
    _write_csv_rows(projection_path, rows[:-1])
    _rewrite_sha256sums(
        candidate_report,
        [
            "candidate_archive_verification_report.json",
            "candidate_archive_verified_projection.csv",
            "verification_inputs.json",
        ],
    )

    with pytest.raises(ValueError, match="candidate_projection_count_invalid"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
        )
    assert not (tmp_path / "finalized").exists()


def test_finalize_replacements_rejects_missing_selected_historical_artifact(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    missing = (
        candidate_run
        / "historical_cases/ca2r-8fe204813ba2bc5d94e9/ca2r-8fe204813ba2bc5d94e9.json"
    )
    missing.unlink()

    with pytest.raises(ValueError, match="candidate_historical_path_invalid"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
        )
    assert not (tmp_path / "finalized").exists()


def test_finalize_replacements_rejects_projection_path_escape(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    projection_path = candidate_report / "candidate_archive_verified_projection.csv"
    projection_rows = _read_csv_rows(projection_path)
    for row in projection_rows:
        if row["candidate_id"] == "ca2r-8fe204813ba2bc5d94e9":
            row["historical_case_path"] = "../escape.json"
            break
    else:
        raise AssertionError("expected candidate row not found")
    _write_csv_rows(projection_path, projection_rows)

    report_path = candidate_report / "candidate_archive_verification_report.json"
    report = _read_json(report_path)
    for row in report["rows"]:
        if row["candidate_id"] == "ca2r-8fe204813ba2bc5d94e9":
            row["historical_case_path"] = "../escape.json"
            break
    else:
        raise AssertionError("expected report row not found")
    _write_json(report_path, _rehash_report(report))
    _rewrite_sha256sums(
        candidate_report,
        [
            "candidate_archive_verification_report.json",
            "candidate_archive_verified_projection.csv",
            "verification_inputs.json",
        ],
    )

    with pytest.raises(ValueError, match="candidate_historical_path_invalid"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
        )


def test_finalize_replacements_selection_follows_raw_order_file_when_promoted_candidate_changes(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    order_path = revision / "slot_candidate_order.csv"
    order_rows = _read_csv_rows(order_path)
    for row in order_rows:
        if row["chain"] != "base":
            continue
        if row["candidate_id"] == "ca2r-358094fa55512d5eb1aa":
            row["global_rank"] = "1"
        elif row["candidate_id"] == "ca2r-1a04f344689dc3f8b499":
            row["global_rank"] = "1001"
    _write_csv_rows(order_path, order_rows)
    _rewrite_sha256sums(revision)
    _sync_candidate_verifier_revision_bindings(candidate_run, candidate_report, revision)

    manifest = _finalize_to_tmp(
        tmp_path,
        parent_run_root=parent_run,
        parent_report_root=parent_report,
        revision_root=revision,
        candidate_run_root=candidate_run,
        candidate_report_root=candidate_report,
        output_name="raw-order-promoted",
    )

    assert manifest["selected_candidate_ids_by_chain"]["base"] == [
        "ca2r-358094fa55512d5eb1aa",
        "ca2r-8fe204813ba2bc5d94e9",
        "ca2r-d88870d32e6a33a7cd53",
    ]


def test_finalize_replacements_selection_is_stable_under_projection_reorder(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    projection_path = candidate_report / "candidate_archive_verified_projection.csv"
    projection_rows = _read_csv_rows(projection_path)
    _write_csv_rows(projection_path, list(reversed(projection_rows)))
    _rewrite_sha256sums(
        candidate_report,
        [
            "candidate_archive_verification_report.json",
            "candidate_archive_verified_projection.csv",
            "verification_inputs.json",
        ],
    )

    manifest = _finalize_to_tmp(
        tmp_path,
        parent_run_root=parent_run,
        parent_report_root=parent_report,
        revision_root=revision,
        candidate_run_root=candidate_run,
        candidate_report_root=candidate_report,
        output_name="reordered",
    )

    assert manifest["selected_candidate_ids_by_chain"] == EXPECTED_SELECTED_BY_CHAIN


def test_finalize_replacements_rejects_candidate_verifier_checksum_tamper(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    checksum_path = candidate_report / "SHA256SUMS.txt"
    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    lines[0] = ("0" * 64) + lines[0][64:]
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="candidate_checksum_mismatch"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_name="tampered-checksums",
        )


def test_finalize_replacements_rejects_candidate_verification_inputs_source_mismatch(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    inputs_path = candidate_report / "verification_inputs.json"
    inputs = _read_json(inputs_path)
    inputs["run_manifest_sha256"] = "0" * 64
    _write_json(inputs_path, inputs)
    _rewrite_sha256sums(
        candidate_report,
        [
            "candidate_archive_verification_report.json",
            "candidate_archive_verified_projection.csv",
            "verification_inputs.json",
        ],
    )

    with pytest.raises(ValueError, match="candidate_verification_inputs_mismatch"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_name="tampered-inputs",
        )


def test_finalize_replacements_rejects_duplicate_candidate_projection_id(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    projection_path = candidate_report / "candidate_archive_verified_projection.csv"
    rows = _read_csv_rows(projection_path)
    rows[1]["candidate_id"] = rows[0]["candidate_id"]
    _write_csv_rows(projection_path, rows)
    _rewrite_sha256sums(
        candidate_report,
        [
            "candidate_archive_verification_report.json",
            "candidate_archive_verified_projection.csv",
            "verification_inputs.json",
        ],
    )

    with pytest.raises(ValueError, match="candidate_projection_duplicate"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_name="duplicate-projection-id",
        )


def test_finalize_replacements_rejects_selected_address_collision(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    screened_path = revision / "screened_candidates.csv"
    rows = _read_csv_rows(screened_path)
    shared_address = "[\"0xcfe0de4a50c80b434092f87e106dfa40b71a5563\"]"
    for row in rows:
        if row["incident_name"] == "BaseBebopSettlement":
            row["target_addresses"] = shared_address
            break
    else:
        raise AssertionError("expected screened candidate not found")
    _write_csv_rows(screened_path, rows)
    _rewrite_sha256sums(revision)
    _sync_candidate_verifier_revision_bindings(candidate_run, candidate_report, revision)

    with pytest.raises(ValueError, match="selected_candidate_address_collision"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_name="address-collision",
        )


def test_finalize_replacements_rejects_selected_tx_collision(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    screened_path = revision / "screened_candidates.csv"
    rows = _read_csv_rows(screened_path)
    shared_tx = "[\"0x8421c96c1cafa451e025c00706599ef82780bdc0db7d17b6263511a420e0cf20\"]"
    for row in rows:
        if row["incident_name"] == "BaseBebopSettlement":
            row["exploit_tx_hashes"] = shared_tx
            break
    else:
        raise AssertionError("expected screened candidate not found")
    _write_csv_rows(screened_path, rows)
    _rewrite_sha256sums(revision)
    _sync_candidate_verifier_revision_bindings(candidate_run, candidate_report, revision)

    with pytest.raises(ValueError, match="selected_candidate_tx_collision"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_name="tx-collision",
        )


def test_finalize_replacements_rejects_revision_order_checksum_tamper(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    checksum_path = revision / "SHA256SUMS.txt"
    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.endswith("slot_candidate_order.csv"):
            lines[index] = ("f" * 64) + line[64:]
            break
    else:
        raise AssertionError("slot_candidate_order.csv checksum line missing")
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="cohort checksum mismatch"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_name="revision-checksum-tamper",
        )


def test_finalize_replacements_rejects_revision_slot_quota_drift(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    slots_path = revision / "replacement_slots.csv"
    rows = _read_csv_rows(slots_path)
    rows[0]["chain"] = "ethereum"
    _write_csv_rows(slots_path, rows)
    _rewrite_sha256sums(revision)

    with pytest.raises(ValueError, match="revision_slot_quota_invalid"):
        _finalize_to_tmp(
            tmp_path,
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_name="slot-quota-drift",
        )


def test_finalize_replacements_rejects_nonempty_output_dir_before_write(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    output_dir = tmp_path / "occupied"
    output_dir.mkdir()
    (output_dir / "placeholder.txt").write_text("occupied\n", encoding="utf-8")

    with pytest.raises(ValueError, match="finalization_output_exists"):
        _module().finalize_historical_snapshot_replacements(
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_dir=output_dir,
        )


def test_finalize_replacements_rejects_symlinked_output_parent_even_when_output_missing(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    symlink_parent = tmp_path / "symlink-parent"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)
    output_dir = symlink_parent / "finalized"

    with pytest.raises(ValueError, match="finalization_output_parent_invalid"):
        _module().finalize_historical_snapshot_replacements(
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_dir=output_dir,
        )


def test_finalize_replacements_rejects_symlinked_output_ancestor_even_when_nested_leaf_missing(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    real_ancestor = tmp_path / "real-ancestor"
    real_ancestor.mkdir()
    symlink_ancestor = tmp_path / "symlink-ancestor"
    symlink_ancestor.symlink_to(real_ancestor, target_is_directory=True)
    output_dir = symlink_ancestor / "nested" / "finalized"

    with pytest.raises(ValueError, match="finalization_output_parent_invalid"):
        _module().finalize_historical_snapshot_replacements(
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_dir=output_dir,
        )


def test_finalize_replacements_rejects_preexisting_symlink_output_leaf(tmp_path: Path) -> None:
    parent_run, parent_report, revision, candidate_run, candidate_report = _fixture_roots(tmp_path)
    real_output = tmp_path / "real-output"
    real_output.mkdir()
    output_dir = tmp_path / "finalized"
    output_dir.symlink_to(real_output, target_is_directory=True)

    with pytest.raises(ValueError, match="finalization_output_parent_invalid"):
        _module().finalize_historical_snapshot_replacements(
            parent_run_root=parent_run,
            parent_report_root=parent_report,
            revision_root=revision,
            candidate_run_root=candidate_run,
            candidate_report_root=candidate_report,
            output_dir=output_dir,
        )
