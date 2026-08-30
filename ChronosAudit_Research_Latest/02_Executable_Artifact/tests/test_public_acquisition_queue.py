from pathlib import Path
import hashlib

import pandas as pd
import pytest
import yaml

from chronosaudit_stage2.public_acquisition.queue import build_case_queue

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def policy() -> dict:
    return yaml.safe_load((ROOT / "config" / "public_acquisition_policy.yaml").read_text(encoding="utf-8"))


@pytest.fixture()
def canonical_cases() -> pd.DataFrame:
    frame = pd.read_csv(ROOT / "processed" / "stage2a_temporal_provenance.csv")
    frame = frame.copy()
    ethereum_index = frame.index[frame["chain"].eq("ethereum")][0]
    base_index = frame.index[frame["chain"].eq("base")][0]
    frame.loc[ethereum_index, "chain"] = "mainnet"
    frame.loc[base_index, "chain"] = "arbi"
    return frame


def test_queue_contains_all_cases_and_frozen_allocation(canonical_cases: pd.DataFrame, policy: dict):
    full, pilot = build_case_queue(canonical_cases, policy, input_sha256="d" * 64)

    assert len(full) == 417
    assert len(pilot) == 10
    assert pilot.chain.value_counts().to_dict() == {"ethereum": 3, "bsc": 3, "base": 2, "arbitrum": 2}
    assert full.loc[full.pilot_member, "priority"].eq(0).all()
    assert full.loc[~full.pilot_member, "priority"].eq(1).all()
    assert full["queue_sha256"].nunique() == 1
    assert full["case_id"].is_unique
    assert full["allocation_satisfied"].all()

def test_queue_records_underfilled_chain_shortfall(policy: dict):
    canonical = pd.read_csv(ROOT / "processed" / "stage2b_onchain_query_queue.csv")
    full, pilot = build_case_queue(canonical, policy, input_sha256="a" * 64)

    assert len(full) == 417
    assert len(pilot) == 9
    arbitrum_rows = full.loc[full["chain"] == "arbitrum"]
    assert arbitrum_rows["pilot_allocation_expected"].eq(2).all()
    assert arbitrum_rows["pilot_allocation_selected"].eq(1).all()
    assert arbitrum_rows["allocation_satisfied"].eq(False).all()


def test_cutoff_requires_explicit_verified_evidence(canonical_cases: pd.DataFrame, policy: dict):
    cases = canonical_cases.copy()
    cases.loc[:, "deployment_block"] = 123456
    cases.loc[:, "prediction_cutoff_block"] = 123999
    cases["source_availability_time"] = "2024-01-02T02:00:00Z"
    cases["temporal_certification"] = "VERIFIED"

    full, _ = build_case_queue(cases, policy, input_sha256="b" * 64)
    assert full["cutoff_status"].eq("PARTIAL").all()

    cases.loc[:, "deployment_verification_status"] = "VERIFIED"
    cases.loc[:, "prediction_cutoff_block_verification_status"] = "VERIFIED"
    cases.loc[:, "source_availability_verification_status"] = "VERIFIED"
    cases.loc[:, "incident_eligibility"] = True
    cases.loc[:, "cutoff_lead_hours"] = 2.0

    verified_full, _ = build_case_queue(cases, policy, input_sha256="c" * 64)
    assert verified_full["cutoff_status"].eq("VERIFIED").all()


def test_input_sha256_binds_file_bytes_even_when_selected_fields_match(canonical_cases: pd.DataFrame, policy: dict, tmp_path: Path):
    frame = canonical_cases.loc[:, ["case_name", "chain", "target_contract_address", "fork_block_number"]].copy()
    path_a = tmp_path / "queue-a.csv"
    path_b = tmp_path / "queue-b.csv"
    text_a = frame.to_csv(index=False)
    text_b = text_a + "\n"
    path_a.write_text(text_a, encoding="utf-8")
    path_b.write_text(text_b, encoding="utf-8")

    hash_a = hashlib.sha256(path_a.read_bytes()).hexdigest()
    hash_b = hashlib.sha256(path_b.read_bytes()).hexdigest()
    assert hash_a != hash_b

    full_a, pilot_a = build_case_queue(pd.read_csv(path_a), policy, input_sha256=hash_a)
    full_b, pilot_b = build_case_queue(pd.read_csv(path_b), policy, input_sha256=hash_b)

    assert full_a["input_sha256"].eq(hash_a).all()
    assert pilot_a["input_sha256"].eq(hash_a).all()
    assert full_b["input_sha256"].eq(hash_b).all()
    assert pilot_b["input_sha256"].eq(hash_b).all()
    assert full_a["queue_sha256"].iat[0] != full_b["queue_sha256"].iat[0]

    with pytest.raises(ValueError, match="input_sha256 must be a 64-character sha256 hex digest"):
        build_case_queue(pd.read_csv(path_a), policy, input_sha256="not-a-hash")
