from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

TRACKED = [
    "raw/incident_evidence_enriched.csv",
    "reports/public_source_provenance.csv",
    "reports/incident_matching_audit.csv",
    "processed/stage2a_temporal_provenance.csv",
    "processed/stage2b_identity_lineage.csv",
    "processed/stage2c_adjudication_queue.csv",
    "processed/stage2d_control_collection_manifest.csv",
    "processed/stage2e_contamination_edges.csv",
    "processed/stage2e_release_cohort.csv",
    "reports/stage2a_2e_audit.json",
]


def sha(path: Path) -> str:
    # The audit has one intentionally observational field (build timestamp).
    # Remove only that field before comparison; all scientific outputs and the
    # terminal registry hash must remain byte/canonical-value reproducible.
    if path.name == "stage2a_2e_audit.json":
        data = json.loads(path.read_text(encoding="utf-8"))
        data.pop("built_at_utc", None)
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description="Deterministic clean-room regeneration check. Does not claim independent human replication.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    before = {p: sha(ROOT / p) for p in TRACKED if (ROOT / p).exists()}
    with tempfile.TemporaryDirectory(prefix="chronosaudit-regenerate-") as td:
        clone = Path(td) / "artifact"
        shutil.copytree(ROOT, clone, ignore=shutil.ignore_patterns(".pytest_cache", "__pycache__", "live_observations"))
        subprocess.run([sys.executable, "enrich_public_evidence.py"], cwd=clone, check=True, capture_output=True, text=True)
        subprocess.run([sys.executable, "run_stage2.py"], cwd=clone, check=True, capture_output=True, text=True)
        after = {p: sha(clone / p) for p in TRACKED if (clone / p).exists()}
    rows = {p: {"baseline": before.get(p), "regenerated": after.get(p), "equal": before.get(p) == after.get(p)} for p in sorted(set(before) | set(after))}
    result = {"status": "deterministic" if all(x["equal"] for x in rows.values()) else "mismatch", "files": rows}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["status"])
        for p, r in rows.items():
            print(f"{p}: {'PASS' if r['equal'] else 'FAIL'}")
    raise SystemExit(0 if result["status"] == "deterministic" else 2)


if __name__ == "__main__":
    main()
