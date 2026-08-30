from pathlib import Path
import json, sys
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from chronosaudit_stage2.evidence_sources import enrich_scone_incidents

result = enrich_scone_incidents(
    ROOT / "raw" / "scone_bench.csv",
    ROOT / "raw" / "external" / "defihacklabs",
    ROOT / "raw" / "incident_evidence_enriched.csv",
    ROOT / "reports" / "public_source_provenance.csv",
    ROOT / "reports" / "incident_matching_audit.csv",
)
print(json.dumps(result, indent=2, sort_keys=True))
