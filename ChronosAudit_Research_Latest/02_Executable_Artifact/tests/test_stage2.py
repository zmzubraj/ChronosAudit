from pathlib import Path
import json, sqlite3, subprocess, sys
import pandas as pd
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from chronosaudit_stage2 import run_all

def test_full_pipeline_fail_closed():
    audit = run_all(ROOT)
    assert audit["stages"]["2A"]["cases"] == 417
    assert audit["stages"]["2A"]["incident_metadata_seeded"] == 417
    assert audit["stages"]["2E"]["exact_identity_leakage"] == 0
    assert audit["stages"]["2E"]["release_eligible_cases"] == 0
    assert audit["decision"].endswith("FAIL_CLOSED")

def test_registry_is_append_only():
    run_all(ROOT)
    db = ROOT / "processed" / "chronosaudit_stage2.sqlite"
    con = sqlite3.connect(db)
    row = con.execute("select id from artifact_record limit 1").fetchone()[0]
    try:
        con.execute("delete from artifact_record where id=?", (row,))
        con.commit()
        assert False, "delete should be blocked"
    except sqlite3.DatabaseError:
        pass
    finally:
        con.close()

def test_reason_codes_present():
    run_all(ROOT)
    df = pd.read_csv(ROOT / "processed" / "stage2a_temporal_provenance.csv")
    assert df.admissibility_reason_codes.notna().all()
    assert (df.temporal_certification == "blocked_missing_onchain_and_availability_evidence").all()

def test_comprehensive_killer_question_loop():
    run_all(ROOT)
    df = pd.read_csv(ROOT / "reports" / "killer_question_fix_loop.csv")
    assert len(df) == 100
    assert set(df.stage) == {"2A", "2B", "2C", "2D", "2E"}
    assert all(df.groupby("stage").size() == 20)
    assert {"PASS", "PASS_BY_DESIGN", "PARTIAL", "BLOCKED"}.issuperset(set(df.final_status))


def test_random_split_leakage_is_exposed():
    audit = run_all(ROOT)
    s = audit["stages"]["2E"]
    assert s["random_split_simulations"] == 1000
    assert s["random_splits_with_exact_identity_leakage"] == 1000
    assert s["mean_crossing_identity_groups_random"] > 0
