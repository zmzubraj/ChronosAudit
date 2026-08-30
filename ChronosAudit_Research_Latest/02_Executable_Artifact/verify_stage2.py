from pathlib import Path
import json
import sqlite3

import pandas as pd

ROOT = Path(__file__).resolve().parent
required = [
    "processed/stage2a_temporal_provenance.csv",
    "processed/stage2b_identity_lineage.csv",
    "processed/stage2c_adjudication_queue.csv",
    "processed/stage2d_control_collection_manifest.csv",
    "processed/stage2e_release_cohort.csv",
    "reports/killer_question_fix_loop.csv",
    "reports/stage2a_2e_audit.json",
    "processed/chronosaudit_stage2.sqlite",
]
missing = [item for item in required if not (ROOT / item).exists()]
if missing:
    raise SystemExit(f"missing outputs: {missing}")

audit = json.loads((ROOT / "reports/stage2a_2e_audit.json").read_text(encoding="utf-8"))
a = pd.read_csv(ROOT / "processed/stage2a_temporal_provenance.csv")
k = pd.read_csv(ROOT / "reports/killer_question_fix_loop.csv")

con = sqlite3.connect(ROOT / "processed/chronosaudit_stage2.sqlite")
rows = con.execute("SELECT COUNT(*) FROM artifact_record").fetchone()[0]
# Verify chain continuity and terminal hash.
records = con.execute(
    "SELECT stage, record_key, payload_json, prev_hash, record_hash FROM artifact_record ORDER BY id"
).fetchall()
con.close()

import hashlib

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

prev = "0" * 64
chain_valid = True
for stage, record_key, payload_json, prev_hash, record_hash in records:
    payload = json.loads(payload_json)
    base = {"stage": stage, "record_key": record_key, "payload": payload, "prev_hash": prev}
    expected = hashlib.sha256((prev + canonical_json(base)).encode()).hexdigest()
    if prev_hash != prev or record_hash != expected:
        chain_valid = False
        break
    prev = record_hash

checks = {
    "cases_417": len(a) == 417,
    "incident_metadata_417": int(a.incident_metadata_present.sum()) == 417,
    "killer_questions_100": len(k) == 100,
    "exact_identity_leakage_zero": audit["stages"]["2E"]["exact_identity_leakage"] == 0,
    "fail_closed_release": audit["stages"]["2E"]["release_eligible_cases"] == 0,
    "registry_populated": rows > 0,
    "registry_hash_chain_valid": chain_valid,
    "terminal_hash_matches": audit["registry"]["terminal_hash"] == prev,
    "public_acquisition_cli_files_present": all(
        [
            (ROOT / "run_public_evidence_acquisition.py").exists(),
            (ROOT / "verify_public_evidence_acquisition.py").exists(),
            (ROOT / "PUBLIC_ACQUISITION_RUNBOOK.md").exists(),
        ]
    ),
}

public_run_root = ROOT / "reports" / "public_acquisition"
if public_run_root.exists():
    from verify_public_evidence_acquisition import evaluate_public_acquisition

    public_result = evaluate_public_acquisition(output_root=ROOT, latest=True)
    checks["public_acquisition_structure_valid"] = bool(public_result["structure_valid"])

result = {
    "checks": checks,
    "pass": all(checks.values()),
    "registry_records": rows,
    "audit_decision": audit["decision"],
}
print(json.dumps(result, indent=2, sort_keys=True))
if not result["pass"]:
    raise SystemExit(1)
