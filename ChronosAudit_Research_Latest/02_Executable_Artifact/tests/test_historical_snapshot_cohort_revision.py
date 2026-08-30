from __future__ import annotations

import csv
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path

import pytest

from chronosaudit_stage2.public_acquisition.cohort_revision import build_cohort_revision


ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT / "raw/historical_snapshots/2026-08-09/historical-snapshots-417-full-20260809"
REPORT = ROOT / "reports/historical-snapshots-417-full-20260809-verification/historical_snapshot_verification_report.json"
INVENTORY = Path("/tmp/defihacklabs-inventory.fyfvOY")


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _build(
    output: Path,
    *,
    staging: Path | None = None,
    parent: Path = PARENT,
    report: Path = REPORT,
    repository: Path | None = None,
) -> dict[str, object]:
    return build_cohort_revision(
        parent_run_root=parent,
        verification_report_path=report,
        candidate_staging_root=staging or INVENTORY / "staging",
        candidate_repository_root=repository or INVENTORY / "repo",
        output_root=output,
        seed="chronosaudit-cohort-revision-v1",
    )


def _rewrite_screened_checksum(staging: Path) -> None:
    checksum_path = staging / "SHA256SUMS.txt"
    digest = hashlib.sha256((staging / "screened_candidates.csv").read_bytes()).hexdigest()
    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    rewritten = []
    for line in lines:
        if line.rsplit("/", 1)[-1] == "screened_candidates.csv":
            rewritten.append(f"{digest}  {staging / 'screened_candidates.csv'}")
        else:
            rewritten.append(line)
    checksum_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def test_builds_frozen_57_slot_plan_with_chain_quotas_and_alternates(tmp_path: Path) -> None:
    before = _tree_hashes(PARENT)
    output = tmp_path / "revision"

    plan = _build(output)

    slots = _read_csv(output / "replacement_slots.csv")
    order = _read_csv(output / "slot_candidate_order.csv")
    assert len(slots) == 57
    assert Counter(row["chain"] for row in slots) == {"ethereum": 16, "bsc": 38, "base": 3}
    assert all(sum(row["slot_case_id"] == slot["slot_case_id"] for row in order) > 1 for slot in slots)
    primaries = [row["candidate_id"] for row in order if row["assignment_role"] == "PRIMARY"]
    assert len(primaries) == len(set(primaries)) == 57
    for chain in {slot["chain"] for slot in slots}:
        chain_slots = [slot for slot in slots if slot["chain"] == chain]
        candidate_orders = [
            [row["candidate_id"] for row in order if row["slot_case_id"] == slot["slot_case_id"]]
            for slot in chain_slots
        ]
        assert candidate_orders and all(candidate_order == candidate_orders[0] for candidate_order in candidate_orders)
    assert plan["selection_contract"]["chain_global_order_frozen"] is True
    assert plan["selection_contract"]["maximizes_same_chain_fill_before_archive_results"] is True
    assert plan["status"] == "WAITING_FOR_ARCHIVE_QUALIFICATION"
    assert plan["no_provider_results_observed"] is True
    assert "final_replacements" not in plan
    assert plan["parent_artifacts"]["run_manifest"]["path"] == str((PARENT / "run_manifest.json").resolve())
    assert plan["parent_artifacts"]["verification_report"]["path"] == str(REPORT.resolve())
    assert _tree_hashes(PARENT) == before

    expected_root = {
        "revision_plan.json",
        "screened_candidates.csv",
        "provenance.json",
        "screening_log.json",
        "source_SHA256SUMS.txt",
        "replacement_slots.csv",
        "slot_candidate_order.csv",
        "SHA256SUMS.txt",
        "candidate_sources",
        "staging",
    }
    assert {path.name for path in output.iterdir()} == expected_root
    checksums = (output / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    assert any(line.endswith("  staging/SHA256SUMS.txt") for line in checksums)
    for line in checksums:
        digest, relative = line.split("  ", 1)
        assert hashlib.sha256((output / relative).read_bytes()).hexdigest() == digest
    for line in (output / "source_SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        assert relative.startswith("staging/")
        assert hashlib.sha256((output / relative).read_bytes()).hexdigest() == digest
    assert "existing_417_comparison_source" not in json.loads((output / "provenance.json").read_text())
    candidates = _read_csv(output / "screened_candidates.csv")
    assert candidates
    for candidate in candidates:
        frozen_source = output / candidate["frozen_source_path"]
        frozen_readme = output / candidate["frozen_readme_path"]
        assert frozen_source.is_file() and frozen_readme.is_file()
        assert hashlib.sha256(frozen_source.read_bytes()).hexdigest() == candidate["source_sha256"]
        assert hashlib.sha256(frozen_readme.read_bytes()).hexdigest() == candidate["readme_sha256"]


def test_candidate_order_is_stable_when_screened_rows_are_shuffled(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    shutil.copytree(INVENTORY / "staging", staging)
    rows = _read_csv(staging / "screened_candidates.csv")
    fields = list(rows[0])
    with (staging / "screened_candidates.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(reversed(rows))
    _rewrite_screened_checksum(staging)

    _build(tmp_path / "original")
    _build(tmp_path / "shuffled", staging=staging)

    assert (tmp_path / "original/slot_candidate_order.csv").read_bytes() == (
        tmp_path / "shuffled/slot_candidate_order.csv"
    ).read_bytes()
    assert (tmp_path / "original/replacement_slots.csv").read_bytes() == (
        tmp_path / "shuffled/replacement_slots.csv"
    ).read_bytes()


def test_parent_collision_is_excluded_from_every_slot_order(tmp_path: Path) -> None:
    output = tmp_path / "revision"
    _build(output)
    parent_rows = _read_csv(PARENT / "frozen_inputs/temporal.csv")
    parent_addresses = {(row["chain"], row["target_contract_address"].lower()) for row in parent_rows}
    candidates = {row["candidate_id"]: row for row in _read_csv(output / "screened_candidates.csv")}
    for order_row in _read_csv(output / "slot_candidate_order.csv"):
        candidate = candidates[order_row["candidate_id"]]
        address = json.loads(candidate["target_addresses"])[0].lower()
        assert (candidate["chain"], address) not in parent_addresses


def test_operational_phishing_incident_is_excluded_with_frozen_reason(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    shutil.copytree(INVENTORY / "staging", staging)
    rows = _read_csv(staging / "screened_candidates.csv")
    phishing = dict(rows[0])
    phishing["incident_name"] = "Bybit phishing credential compromise"
    phishing["mechanism"] = "social engineering and private-key compromise"
    phishing["target_addresses"] = '["0x1111111111111111111111111111111111111111"]'
    phishing["exploit_tx_hashes"] = '["0x' + "1" * 64 + '"]'
    fields = list(rows[0])
    with (staging / "screened_candidates.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows([*rows, phishing])
    _rewrite_screened_checksum(staging)

    plan = _build(tmp_path / "revision", staging=staging)

    assert "non_smart_contract_operational_incident" in plan["operational_scope_exclusion_codes"]
    assert plan["candidate_exclusion_counts"]["non_smart_contract_operational_incident"] >= 1
    frozen = _read_csv(tmp_path / "revision/screened_candidates.csv")
    assert all(row["incident_name"] != phishing["incident_name"] for row in frozen)


def test_mev_reference_is_allowed_but_mev_only_is_excluded(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    shutil.copytree(INVENTORY / "staging", staging)
    rows = _read_csv(staging / "screened_candidates.csv")
    allowed = dict(rows[0])
    allowed["incident_name"] = "Contract exploit with MEV aftermath"
    allowed["mechanism"] = "reentrancy exploited before MEV searchers reacted"
    allowed["target_addresses"] = '["0x2222222222222222222222222222222222222222"]'
    allowed["exploit_tx_hashes"] = '["0x' + "2" * 64 + '"]'
    excluded = dict(rows[0])
    excluded["incident_name"] = "MEV-only arbitrage incident"
    excluded["mechanism"] = "sandwich-only operation"
    excluded["target_addresses"] = '["0x3333333333333333333333333333333333333333"]'
    excluded["exploit_tx_hashes"] = '["0x' + "3" * 64 + '"]'
    fields = list(rows[0])
    with (staging / "screened_candidates.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows([*rows, allowed, excluded])
    _rewrite_screened_checksum(staging)

    plan = _build(tmp_path / "revision", staging=staging)
    names = {row["incident_name"] for row in _read_csv(tmp_path / "revision/screened_candidates.csv")}

    assert allowed["incident_name"] in names
    assert excluded["incident_name"] not in names
    assert plan["candidate_exclusion_counts"]["non_smart_contract_operational_incident"] >= 1


def test_rejects_unsafe_staging_candidate_columns_before_write(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    shutil.copytree(INVENTORY / "staging", staging)
    rows = _read_csv(staging / "screened_candidates.csv")
    fields = [*rows[0], "provider_result"]
    with (staging / "screened_candidates.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(({**row, "provider_result": "secret-token"} for row in rows))
    _rewrite_screened_checksum(staging)
    output = tmp_path / "revision"

    with pytest.raises(ValueError, match="candidate_forbidden_column:provider_result"):
        _build(output, staging=staging)

    assert not output.exists()


def test_stale_candidate_checksum_fails_before_any_write(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    shutil.copytree(INVENTORY / "staging", staging)
    with (staging / "screened_candidates.csv").open("a", encoding="utf-8") as handle:
        handle.write("\n")
    output = tmp_path / "revision"

    with pytest.raises(ValueError, match="candidate_checksum_mismatch"):
        _build(output, staging=staging)

    assert not output.exists()


def test_stale_parent_hash_fails_before_any_write(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    shutil.copytree(PARENT, parent)
    with (parent / "blocker_ledger.csv").open("a", encoding="utf-8") as handle:
        handle.write("\n")
    output = tmp_path / "revision"

    with pytest.raises(ValueError, match="parent_blocker_hash_mismatch"):
        _build(output, parent=parent)

    assert not output.exists()


def test_rejects_candidate_source_with_symlinked_directory_ancestor_before_write(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    shutil.copytree(INVENTORY / "staging", staging)
    repository = tmp_path / "repo"
    repository.mkdir()
    rows = _read_csv(staging / "screened_candidates.csv")
    for row in rows:
        for field in ("source_path", "readme_path"):
            source = INVENTORY / "repo" / row[field]
            destination = repository / row[field]
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                shutil.copyfile(source, destination)
    (repository / "alias").symlink_to(repository / "src/test/2017-07", target_is_directory=True)
    fields = list(rows[0])
    rows[0]["source_path"] = "alias/Parity_first_hack_exp.sol"
    with (staging / "screened_candidates.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    _rewrite_screened_checksum(staging)
    output = tmp_path / "revision"

    with pytest.raises(ValueError, match="candidate_source_path_symlink"):
        _build(output, staging=staging, repository=repository)

    assert not output.exists()
