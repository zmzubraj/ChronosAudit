from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent

def run(cmd):
    p=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,check=True)
    return p.stdout.strip()

print(run([sys.executable,'enrich_public_evidence.py']))
print(run([sys.executable,'run_stage2.py']))
print(run([sys.executable,'create_reviewer_packets.py']))
print(run([sys.executable,'run_live_stage2_evidence.py']))
