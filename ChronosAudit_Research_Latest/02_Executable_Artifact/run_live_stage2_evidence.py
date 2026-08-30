from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.public_acquisition.ledger import AppendOnlyLedger
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry
from chronosaudit_stage2.public_acquisition.queue import build_case_queue
from chronosaudit_stage2.public_acquisition.rpc import acquire_queue, public_provider_objects


def main():
    parser = argparse.ArgumentParser(description="Resumable live Stage-2 evidence collector. Secrets are read only from environment variables.")
    parser.add_argument("--execute", action="store_true", help="Actually perform network calls; without this flag the command is a capability/dry-run report.")
    parser.add_argument("--limit", type=int, default=0, help="Optional number of cases to process; 0 means all.")
    parser.add_argument(
        "--legacy-output",
        type=Path,
        default=None,
        help="Optional JSON path for the dry-run/execution summary. Legacy locations are not written implicitly.",
    )
    args = parser.parse_args()

    queue_path = ROOT / "processed" / "stage2b_onchain_query_queue.csv"
    cases = pd.read_csv(queue_path)
    policy = json.loads(json.dumps(yaml_safe_load(ROOT / "config" / "public_acquisition_policy.yaml")))
    full_queue, pilot_queue = build_case_queue(cases, policy, input_sha256=hashlib.sha256(queue_path.read_bytes()).hexdigest())
    if args.limit > 0:
        full_queue = full_queue.head(args.limit).reset_index(drop=True)
        pilot_queue = pilot_queue.head(min(args.limit, len(pilot_queue))).reset_index(drop=True)

    registry = ProviderRegistry.from_path(ROOT / "config" / "public_provider_registry.yaml")
    chain_counts = full_queue.chain.value_counts().to_dict()
    readiness = {}
    for chain in sorted(full_queue.chain.unique()):
        providers = public_provider_objects(chain, registry)
        readiness[chain] = {"configured_archive_provider_urls": len(providers), "meets_two_provider_minimum": len(providers) >= 2}

    summary = {
        "mode": "execute" if args.execute else "dry_run",
        "cases": len(full_queue),
        "pilot_cases": len(pilot_queue),
        "chain_counts": chain_counts,
        "provider_readiness": readiness,
        "legacy_output_enabled": bool(args.legacy_output),
        "etherscan_key_present": bool(os.getenv("ETHERSCAN_API_KEY")),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))

    ledger = AppendOnlyLedger(ROOT / "raw" / "public_acquisition" / "events.jsonl")
    result = acquire_queue(
        full_queue,
        policy,
        registry=registry,
        ledger=ledger,
        execute=args.execute,
        artifact_root=ROOT / "raw" / "public_acquisition" / "responses",
    )
    if args.legacy_output is not None:
        args.legacy_output.parent.mkdir(parents=True, exist_ok=True)
        args.legacy_output.write_text(json.dumps({"summary": summary, "result": result}, indent=2, sort_keys=True), encoding="utf-8")


def yaml_safe_load(path: Path) -> dict:
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
