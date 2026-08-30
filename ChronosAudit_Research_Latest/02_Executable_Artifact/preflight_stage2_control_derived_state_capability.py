from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from chronosaudit_stage2.onchain import JsonRpcProvider
from chronosaudit_stage2.public_acquisition.control_derived_state_capability import assess_derived_state_capability, verify_derived_state_capability
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class _Paced:
    def __init__(self, provider: JsonRpcProvider, chain: str, interval: float) -> None:
        self._provider = provider
        self.provider_id = provider.provider_id
        self.provider_family = provider.provider_family
        self.chain = chain
        self._interval = interval
        self._last = 0.0

    def call(self, method: str, params: list[object]):
        remaining = self._interval - (time.monotonic() - self._last)
        if remaining > 0:
            time.sleep(remaining)
        result = self._provider.call(method, params)
        self._last = time.monotonic()
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe exact Phase 2 targets through both bound provider families; outputs are non-authorizing.")
    parser.add_argument("--derived-state-targets", type=Path, required=True)
    parser.add_argument("--provider-registry", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--output-capability", type=Path, required=True)
    parser.add_argument("--output-verification", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--minimum-interval-seconds", type=float, default=0.15)
    args = parser.parse_args()
    targets_path = args.derived_state_targets.expanduser().resolve(strict=True)
    targets = json.loads(targets_path.read_text(encoding="utf-8"))["targets"]
    bindings: dict[str, tuple[str, str]] = {}
    for target in targets:
        for call in target["calls"]:
            bindings[call["provider_id"]] = (target["chain"], call["operator_family"])
    registry_path = args.provider_registry.expanduser().resolve(strict=True)
    records = {row.provider_id: row for row in ProviderRegistry.from_path(registry_path).providers}
    providers = []
    for provider_id, (chain, family) in sorted(bindings.items()):
        record = records[provider_id]
        if record.chain != chain or record.operator_family != family or not record.operator_verified or not record.tracking_enabled:
            raise ValueError("provider_registry_mismatch")
        providers.append(_Paced(JsonRpcProvider(provider_id=record.provider_id, url=record.resolved_endpoint(), timeout=args.timeout_seconds, max_retries=0, provider_family=record.operator_family), chain, args.minimum_interval_seconds))
    capability = assess_derived_state_capability(derived_state_targets_path=targets_path, provider_registry_path=registry_path, providers=providers, raw_root=args.raw_root)
    capability_path = args.output_capability.expanduser().resolve(strict=False)
    _write(capability_path, capability)
    if capability["complete"] is not True:
        print(json.dumps(capability, indent=2, sort_keys=True))
        return 3
    verification = verify_derived_state_capability(capability_path=capability_path, derived_state_targets_path=targets_path, provider_registry_path=registry_path, raw_root=args.raw_root)
    _write(args.output_verification.expanduser().resolve(strict=False), verification)
    print(json.dumps(verification, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
