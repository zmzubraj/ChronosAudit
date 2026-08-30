from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from chronosaudit_stage2.onchain import ProviderObservation

from .providers import ProviderRegistry


class ControlCandidateRpcCapabilityError(ValueError):
    """Raised when exact candidate-RPC capability evidence is invalid."""


REPORT_SCHEMA = "stage2_control_candidate_rpc_capability.v1"
VERIFICATION_SCHEMA = "stage2_control_candidate_rpc_capability_verification.v1"
FALSE_FLAGS = (
    "rpc_authorized",
    "selection_authorized",
    "stage_promotion_authorized",
    "recovery3_mutation_authorized",
)


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(json.dumps(dict(payload), sort_keys=True, separators=(",", ":")) + "\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _result(observation: object, method: str) -> object:
    if not isinstance(observation, ProviderObservation):
        raise ControlCandidateRpcCapabilityError("provider_observation_invalid")
    if observation.error is not None or observation.result is None:
        raise ControlCandidateRpcCapabilityError(f"rpc_error:{method}")
    return observation.result


def assess_candidate_rpc_capability(
    *, fixtures: Sequence[Mapping[str, object]], providers: Sequence[object], raw_root: Path
) -> dict[str, object]:
    root = raw_root.expanduser().resolve(strict=False)
    root.mkdir(parents=True, exist_ok=True)
    by_chain: dict[str, list[object]] = {}
    for provider in providers:
        by_chain.setdefault(str(provider.chain), []).append(provider)
    fixture_by_chain = {str(row["chain"]): row for row in fixtures}
    if sorted(by_chain) != sorted(fixture_by_chain):
        raise ControlCandidateRpcCapabilityError("fixture_provider_chain_scope_mismatch")

    chain_reports = []
    evidence = []
    for chain in sorted(fixture_by_chain):
        fixture = fixture_by_chain[chain]
        chain_providers = sorted(by_chain[chain], key=lambda row: row.provider_id)
        if len(chain_providers) != 2 or len({row.provider_family for row in chain_providers}) != 2:
            raise ControlCandidateRpcCapabilityError(f"provider_pair_invalid:{chain}")
        semantics = []
        provider_reports = []
        for provider in chain_providers:
            calls = (
                ("eth_chainId", []),
                ("eth_getTransactionReceipt", [fixture["transaction_hash"]]),
                ("eth_getBlockByHash", [fixture["block_hash"], False]),
            )
            results = {}
            for method, params in calls:
                observation = provider.call(method, params)
                result = _result(observation, method)
                envelope = {
                    "schema_version": "stage2_control_candidate_rpc_capability_evidence.v1",
                    "chain": chain,
                    "provider_id": provider.provider_id,
                    "provider_family": provider.provider_family,
                    "method": method,
                    "params": params,
                    "result": result,
                    "error": observation.error,
                    "observed_at_utc": observation.observed_at_utc,
                }
                digest = _canonical_sha(envelope)
                path = root / f"{chain}-{provider.provider_id}-{method}-{digest}.json"
                _atomic_json(path, envelope)
                evidence.append({"path": path.relative_to(root).as_posix(), "sha256": _file_sha(path)})
                results[method] = result
            receipt = results["eth_getTransactionReceipt"]
            block = results["eth_getBlockByHash"]
            if not isinstance(receipt, Mapping) or not isinstance(block, Mapping):
                raise ControlCandidateRpcCapabilityError(f"candidate_payload_invalid:{chain}")
            semantic = {
                "chain_id": str(results["eth_chainId"]).lower(),
                "transaction_hash": str(receipt.get("transactionHash") or "").lower(),
                "receipt_block_hash": str(receipt.get("blockHash") or "").lower(),
                "receipt_block_number": str(receipt.get("blockNumber") or "").lower(),
                "block_hash": str(block.get("hash") or "").lower(),
                "block_number": str(block.get("number") or "").lower(),
                "block_timestamp": str(block.get("timestamp") or "").lower(),
            }
            expected = {
                "chain_id": str(fixture["chain_id"]).lower(),
                "transaction_hash": str(fixture["transaction_hash"]).lower(),
                "receipt_block_hash": str(fixture["block_hash"]).lower(),
                "receipt_block_number": hex(int(fixture["block_number"])),
                "block_hash": str(fixture["block_hash"]).lower(),
                "block_number": hex(int(fixture["block_number"])),
            }
            if any(semantic[key] != value for key, value in expected.items()):
                raise ControlCandidateRpcCapabilityError(f"candidate_semantic_mismatch:{chain}")
            semantics.append(_canonical_sha(semantic))
            provider_reports.append({
                "provider_id": provider.provider_id,
                "provider_family": provider.provider_family,
                "semantic_sha256": semantics[-1],
            })
        if len(set(semantics)) != 1:
            raise ControlCandidateRpcCapabilityError(f"provider_disagreement:{chain}")
        chain_reports.append({"chain": chain, "complete": True, "providers": provider_reports})

    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA,
        "complete": True,
        "chain_count": len(chain_reports),
        "chains": chain_reports,
        "raw_evidence_count": len(evidence),
        "raw_evidence": evidence,
        "errors": [],
        **{field: False for field in FALSE_FLAGS},
    }
    report["report_sha256"] = _canonical_sha(report)
    return report


def verify_candidate_rpc_capability(
    *, report_path: Path, raw_root: Path, provider_registry_path: Path
) -> dict[str, object]:
    report_file = report_path.expanduser().resolve(strict=True)
    report = json.loads(report_file.read_text(encoding="utf-8"))
    material = {key: value for key, value in report.items() if key != "report_sha256"}
    errors = []
    if report.get("schema_version") != REPORT_SCHEMA or report.get("report_sha256") != _canonical_sha(material):
        errors.append("report_binding_invalid")
    if report.get("complete") is not True or report.get("errors") != []:
        errors.append("report_not_complete")
    if any(report.get(field) is not False for field in FALSE_FLAGS):
        errors.append("report_authority_invalid")
    root = raw_root.expanduser().resolve(strict=True)
    entries = report.get("raw_evidence") if isinstance(report.get("raw_evidence"), list) else []
    for entry in entries:
        path = (root / str(entry.get("path"))).resolve(strict=True)
        if root not in path.parents or path.is_symlink() or _file_sha(path) != entry.get("sha256"):
            errors.append("raw_evidence_invalid")
            break
    registry = ProviderRegistry.from_path(provider_registry_path)
    observed_chains = {
        str(chain.get("chain") or "")
        for chain in report.get("chains", [])
        if isinstance(chain, Mapping)
    }
    expected = sorted(
        (row.chain, row.provider_id, row.operator_family)
        for row in registry.providers
        if row.chain in observed_chains and row.tracking_enabled and row.operator_verified
    )
    observed = sorted(
        (chain["chain"], provider["provider_id"], provider["provider_family"])
        for chain in report.get("chains", [])
        for provider in chain.get("providers", [])
    )
    if observed != expected:
        errors.append("provider_registry_scope_mismatch")
    verification: dict[str, object] = {
        "schema_version": VERIFICATION_SCHEMA,
        "complete": not errors,
        "report_sha256": report.get("report_sha256"),
        "report_file_sha256": _file_sha(report_file),
        "provider_registry_sha256": _file_sha(provider_registry_path),
        "chain_count": report.get("chain_count"),
        "raw_evidence_count": report.get("raw_evidence_count"),
        "errors": sorted(set(errors)),
        **{field: False for field in FALSE_FLAGS},
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    return verification
