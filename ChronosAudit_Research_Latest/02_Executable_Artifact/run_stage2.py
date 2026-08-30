from pathlib import Path
import json, sys
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from chronosaudit_stage2 import run_all
print(json.dumps(run_all(ROOT), indent=2, sort_keys=True))
