from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'src'))
from chronosaudit_stage2.review_workflow import create_blinded_reviewer_packets

result=create_blinded_reviewer_packets(
    ROOT/'raw'/'incident_evidence_enriched.csv',
    ROOT/'review'/'reviewer_A_blinded.csv',
    ROOT/'review'/'reviewer_B_blinded.csv',
)
print(result)
