from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import tempfile
import time
from typing import Any, Mapping

import pandas as pd

from chronosaudit_stage2.onchain import JsonRpcProvider

from .providers import endpoint_id


class ControlBlockWindowResolutionError(ValueError):
    """Raised when a local-test block boundary cannot be resolved exactly."""


CHAIN_IDS = {"ethereum": 1, "bsc": 56, "base": 8453, "arbitrum": 42161}
ARCHIVE_ENDPOINTS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "bsc": "https://bsc-rpc.publicnode.com",
    "base": "https://mainnet.base.org",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
}


def _rpc_quantity(value: object, label: str) -> int:
    text = str(value or "")
    if not text.startswith("0x"):
        raise ControlBlockWindowResolutionError(f"provider_{label}_invalid")
    try:
        return int(text, 16)
    except ValueError as exc:
        raise ControlBlockWindowResolutionError(f"provider_{label}_invalid") from exc


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _transient_rpc_error(value: object) -> bool:
    text = str(value or "").lower()
    return any(token in text for token in ("429", "too many requests", "503", "server unavailable"))


def _block_header_call(
    provider: JsonRpcProvider, block_number: int, *, attempts: int = 8
) -> Any:
    last = None
    for attempt in range(attempts):
        observation = provider.call("eth_getBlockByNumber", [hex(block_number), False])
        last = observation
        if not observation.error and isinstance(observation.result, dict):
            return observation
        failure = observation.error if observation.error else observation.result
        if not _transient_rpc_error(failure) or attempt + 1 == attempts:
            return observation
        time.sleep(min(8.0, 0.5 * (2**attempt)))
    return last


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(json.dumps(dict(value), indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def last_block_at_or_before(search: Mapping[str, Any]) -> int:
    target = int(search["target_timestamp"])
    cutoff = search["cutoff_block"]
    previous = search["previous_block"]
    return int(cutoff["number"]) if int(cutoff["timestamp"]) == target else int(previous["number"])


def first_accessible_block_anchor(
    provider: JsonRpcProvider,
    *,
    upper_block: int,
    earliest_target_timestamp: int,
) -> dict[str, Any]:
    """Find the earliest header this endpoint can serve and prove it precedes scope."""

    def observe(block_number: int) -> tuple[bool, dict[str, Any] | None]:
        observation = _block_header_call(provider, block_number)
        if observation.error or not isinstance(observation.result, dict):
            return False, None
        return True, {
            "number": int(str(observation.result["number"]), 16),
            "hash": str(observation.result["hash"]).lower(),
            "timestamp": int(str(observation.result["timestamp"]), 16),
            "response_sha256": str(observation.response_sha256),
        }

    genesis_available, genesis = observe(0)
    if genesis_available:
        anchor = genesis
    else:
        head_available, head = observe(upper_block)
        if not head_available:
            raise RuntimeError("latest block header unavailable while locating history anchor")
        lo = 0
        hi = upper_block
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            available, _ = observe(mid)
            if available:
                hi = mid
            else:
                lo = mid
        available, anchor = observe(hi)
        if not available:
            raise RuntimeError("accessible history anchor invariant failed")
    assert anchor is not None
    if int(anchor["timestamp"]) >= earliest_target_timestamp:
        raise ValueError("first accessible block is not before the earliest target")
    return anchor


def first_block_at_or_after_timestamp_interpolated(
    provider: JsonRpcProvider,
    *,
    target_timestamp: int,
    lower_block: int,
    upper_block: int,
) -> dict[str, Any]:
    """Resolve an exact timestamp bracket with interpolation-guided bisection."""
    if lower_block < 0 or upper_block <= lower_block:
        raise ValueError("invalid timestamp-search bounds")

    def header(block_number: int) -> tuple[dict[str, Any], dict[str, Any]]:
        observation = _block_header_call(provider, block_number)
        if observation.error or not isinstance(observation.result, dict):
            raise RuntimeError(
                f"block header unavailable at {block_number}: {observation.error}"
            )
        value = {
            "number": int(str(observation.result["number"]), 16),
            "hash": str(observation.result["hash"]).lower(),
            "timestamp": int(str(observation.result["timestamp"]), 16),
        }
        return dict(observation.__dict__), value

    lower_observation, lower = header(lower_block)
    upper_observation, upper = header(upper_block)
    if lower["timestamp"] >= target_timestamp:
        raise ValueError("lower search bound is not before the target timestamp")
    if upper["timestamp"] < target_timestamp:
        raise ValueError("upper search bound is before the target timestamp")
    observations = [lower_observation, upper_observation]
    lo = lower
    hi = upper
    for _ in range(128):
        if int(lo["number"]) + 1 >= int(hi["number"]):
            break
        timestamp_span = int(hi["timestamp"]) - int(lo["timestamp"])
        if timestamp_span <= 0:
            estimate = (int(lo["number"]) + int(hi["number"])) // 2
        else:
            estimate = int(lo["number"]) + (
                (target_timestamp - int(lo["timestamp"]))
                * (int(hi["number"]) - int(lo["number"]))
                // timestamp_span
            )
        block_span = int(hi["number"]) - int(lo["number"])
        midpoint = int(lo["number"]) + block_span // 2
        lower_guard = int(lo["number"]) + max(1, block_span // 10)
        upper_guard = int(hi["number"]) - max(1, block_span // 10)
        if estimate < lower_guard or estimate > upper_guard:
            estimate = midpoint
        estimate = max(int(lo["number"]) + 1, min(int(hi["number"]) - 1, estimate))
        observation, value = header(estimate)
        observations.append(observation)
        if int(value["timestamp"]) >= target_timestamp:
            hi = value
        else:
            lo = value
    else:
        raise RuntimeError("interpolated timestamp search iteration limit exceeded")
    if not (int(lo["timestamp"]) < target_timestamp <= int(hi["timestamp"])):
        raise RuntimeError("timestamp landmark bracket invariant failed")
    return {
        "target_timestamp": target_timestamp,
        "previous_block": lo,
        "cutoff_block": hi,
        "binary_search_observations": observations,
    }


def _compact_search(search: Mapping[str, Any]) -> dict[str, Any]:
    observations = search.get("binary_search_observations") or []
    return {
        "target_timestamp": int(search["target_timestamp"]),
        "previous_block": dict(search["previous_block"]),
        "cutoff_block": dict(search["cutoff_block"]),
        "observation_count": len(observations),
        "observation_response_sha256": sorted(
            {
                str(item.get("response_sha256") or "")
                for item in observations
                if isinstance(item, Mapping) and item.get("response_sha256")
            }
        ),
    }


def resolve_control_block_windows(
    *,
    chunk_plan_path: Path,
    source_import_manifest_path: Path,
    output_csv_path: Path,
    output_manifest_path: Path,
    receipt_root: Path,
    endpoints: Mapping[str, str] | None = None,
    workers: int = 16,
) -> dict[str, Any]:
    chunks = pd.read_csv(chunk_plan_path, dtype=str, keep_default_na=False)
    required = {
        "case_name",
        "chain",
        "admissible_deployment_start",
        "admissible_deployment_end",
        "positive_prediction_cutoff_time",
        "expansion_requirement_sha256",
    }
    if missing := sorted(required - set(chunks.columns)):
        raise ControlBlockWindowResolutionError(f"chunk_columns_missing:{','.join(missing)}")
    if chunks["case_name"].duplicated().any():
        raise ControlBlockWindowResolutionError("chunk_case_duplicate")
    configured = dict(endpoints or ARCHIVE_ENDPOINTS)
    chains = sorted(set(chunks["chain"].str.lower()))
    if set(chains) - set(configured):
        raise ControlBlockWindowResolutionError("endpoint_chain_coverage_incomplete")

    targets: set[tuple[str, int]] = set()
    for row in chunks.to_dict("records"):
        chain = str(row["chain"]).lower()
        for field in ("admissible_deployment_start", "admissible_deployment_end"):
            parsed = pd.to_datetime(row[field], utc=True, errors="coerce")
            if pd.isna(parsed):
                raise ControlBlockWindowResolutionError(f"chunk_time_invalid:{field}")
            targets.add((chain, int(parsed.timestamp())))
    earliest_targets = {
        chain: min(timestamp for target_chain, timestamp in targets if target_chain == chain)
        for chain in chains
    }

    providers: dict[str, JsonRpcProvider] = {}
    latest: dict[str, int] = {}
    lower_anchors: dict[str, dict[str, Any]] = {}
    provider_bindings: list[dict[str, Any]] = []
    for chain in chains:
        if "1rpc.io" in configured[chain]:
            family = "1rpc"
        elif "mainnet.base.org" in configured[chain]:
            family = "base-official"
        else:
            family = "publicnode"
        provider = JsonRpcProvider(
            provider_id=f"{family}-{chain}-local-test",
            url=configured[chain],
            timeout=30,
            max_retries=3,
            backoff_seconds=0.25,
            provider_family=f"{family}-local-test-non-independent",
            artifact_root=receipt_root / chain,
        )
        chain_id = provider.call("eth_chainId", [])
        head = provider.call("eth_blockNumber", [])
        if chain_id.error or head.error:
            raise ControlBlockWindowResolutionError(f"provider_preflight_failed:{chain}")
        if _rpc_quantity(chain_id.result, "chain_id") != CHAIN_IDS[chain]:
            raise ControlBlockWindowResolutionError(f"provider_chain_id_mismatch:{chain}")
        providers[chain] = provider
        latest[chain] = _rpc_quantity(head.result, "head")
        try:
            lower_anchors[chain] = first_accessible_block_anchor(
                provider,
                upper_block=latest[chain],
                earliest_target_timestamp=earliest_targets[chain],
            )
        except Exception as exc:
            raise ControlBlockWindowResolutionError(
                f"provider_history_insufficient:{chain}:{type(exc).__name__}"
            ) from exc
        provider_bindings.append(
            {
                "chain": chain,
                "chain_id": CHAIN_IDS[chain],
                "provider_id": provider.provider_id,
                "operator_family": provider.provider_family,
                "endpoint_id": endpoint_id(configured[chain]),
                "latest_block": latest[chain],
                "lower_anchor": lower_anchors[chain],
                "chain_id_response_sha256": chain_id.response_sha256,
                "head_response_sha256": head.response_sha256,
            }
        )

    cache_root = receipt_root / "boundary-cache"
    resolved: dict[tuple[str, int], dict[str, Any]] = {}
    pending: set[tuple[str, int]] = set()
    for chain, timestamp in sorted(targets):
        cache_path = cache_root / f"{chain}-{timestamp}.json"
        if cache_path.is_file() and not cache_path.is_symlink():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                cached = None
            if (
                isinstance(cached, dict)
                and cached.get("chain") == chain
                and int(cached.get("target_timestamp") or -1) == timestamp
                and isinstance(cached.get("search"), dict)
            ):
                resolved[(chain, timestamp)] = dict(cached["search"])
                continue
        pending.add((chain, timestamp))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(
                first_block_at_or_after_timestamp_interpolated,
                providers[chain],
                target_timestamp=timestamp,
                lower_block=int(lower_anchors[chain]["number"]),
                upper_block=latest[chain],
            ): (chain, timestamp)
            for chain, timestamp in sorted(pending)
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                resolved[key] = _compact_search(future.result())
                _atomic_json(
                    cache_root / f"{key[0]}-{key[1]}.json",
                    {"chain": key[0], "target_timestamp": key[1], "search": resolved[key]},
                )
            except Exception as exc:
                raise ControlBlockWindowResolutionError(
                    f"boundary_resolution_failed:{key[0]}:{key[1]}:{type(exc).__name__}"
                ) from exc

    records: list[dict[str, Any]] = []
    for row in chunks.sort_values("case_name", kind="stable").to_dict("records"):
        chain = str(row["chain"]).lower()
        start_ts = int(pd.to_datetime(row["admissible_deployment_start"], utc=True).timestamp())
        end_ts = int(pd.to_datetime(row["admissible_deployment_end"], utc=True).timestamp())
        start_search = resolved[(chain, start_ts)]
        end_search = resolved[(chain, end_ts)]
        start_block = int(start_search["cutoff_block"]["number"])
        end_block = last_block_at_or_before(end_search)
        if start_block > end_block:
            raise ControlBlockWindowResolutionError(f"empty_block_window:{row['case_name']}")
        material = {
            "case_name": str(row["case_name"]),
            "chain": chain,
            "chain_id": CHAIN_IDS[chain],
            "admissible_deployment_start": str(row["admissible_deployment_start"]),
            "admissible_deployment_end": str(row["admissible_deployment_end"]),
            "start_block": start_block,
            "end_block": end_block,
            "start_boundary_sha256": _canonical_sha(start_search),
            "end_boundary_sha256": _canonical_sha(end_search),
            "expansion_requirement_sha256": str(row["expansion_requirement_sha256"]),
            "boundary_status": "LOCAL_TEST_SINGLE_PROVIDER_EXACT_BLOCK_BRACKET",
        }
        material["block_window_sha256"] = _canonical_sha(material)
        records.append(material)

    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(records).to_csv(output_csv_path, index=False)
    receipt_files = sorted(
        path
        for chain in chains
        for path in (receipt_root / chain).rglob("*.json")
        if path.is_file()
    )
    receipt_index = [{"path": str(path), "sha256": _sha(path)} for path in receipt_files]
    manifest = {
        "schema_version": "chronosaudit.control_block_window_resolution.local_test.v1",
        "decision": "LOCAL_TEST_BLOCK_WINDOWS_RESOLVED_NON_AUTHORIZING",
        "chunk_plan_sha256": _sha(chunk_plan_path),
        "source_import_manifest_sha256": _sha(source_import_manifest_path),
        "provider_bindings": provider_bindings,
        "boundary_target_count": len(targets),
        "boundary_target_cache_count": len(resolved),
        "case_count": len(records),
        "output_csv_sha256": _sha(output_csv_path),
        "rpc_receipt_count": len(receipt_index),
        "rpc_receipts_sha256": _canonical_sha(receipt_index),
        "single_provider_non_independent": True,
        "local_test_only": True,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    output_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    output_manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest
