from pathlib import Path
import json, sys
import pandas as pd
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
from chronosaudit_stage2.split_audit import audit_split_strategies

df=pd.read_csv(ROOT/'raw'/'scone_bench.csv')
r=audit_split_strategies(df)
out=ROOT/'reports'/'split_baseline_audit.json'; out.write_text(json.dumps(r,indent=2,sort_keys=True))
print(json.dumps(r,indent=2,sort_keys=True))
