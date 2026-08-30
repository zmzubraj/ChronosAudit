from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from chronosaudit_stage2.public_acquisition.control_provider_identity_legacy_alias_registry_projection import (
    ControlProviderIdentityLegacyAliasRegistryProjectionError,
    build_legacy_alias_full_registry_projection,
)


CHAINS = ["base", "bsc", "ethereum"]
LEGACY_ENDPOINTS = {
    "base": "https://base.merkle.io",
    "bsc": "https://bsc.merkle.io",
    "ethereum": "https://eth.merkle.io",
}
PAIRED = {
    "base": ("drpc-base", "drpc"),
    "bsc": ("nodereal-bsc", "nodereal"),
    "ethereum": ("quicknode-ethereum", "quicknode"),
}
EXECUTABLE_ROOT = Path(__file__).resolve().parents[1]
FALSE_AUTHORITY = {
    "rpc_authorized": False,
    "denominator_admission_authorized": False,
    "row_admission_authorized": False,
    "selection_authorized": False,
    "qualification_authorized": False,
    "counter_authority": False,
    "stage_promotion_authorized": False,
    "recovery3_mutation_authorized": False,
    "independent_review_established": False,
    "r5_authorized": False,
    "release_authorized": False,
    "publication_authorized": False,
}


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def _inputs(tmp_path: Path) -> dict[str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    revision_sha = "1" * 64
    target_identities_sha = "2" * 64
    trace_targets: dict[str, object] = {
        "schema_version": "stage2_control_trace_targets.v1",
        "target_identities_sha256": target_identities_sha,
        "capability_report_file_sha256": "pending",
        "capability_report_sha256": "pending",
        "target_count": 3,
        "rpc_call_count": 6,
        "targets": [],
        "provider_registry_verified": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    capability: dict[str, object] = {
        "schema_version": "stage2_control_trace_state_capability.v1",
        "complete": True,
        "chain_count": 3,
        "chains": [],
        "errors": [],
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    registry_rows = []
    identity_chains = []
    fragment_rows = []
    for index, chain in enumerate(CHAINS, start=1):
        legacy_id = f"merkle-{chain}"
        paired_id, paired_family = PAIRED[chain]
        capability["chains"].append(
            {
                "chain": chain,
                "complete": True,
                "providers": [
                    {
                        "provider_id": legacy_id,
                        "provider_family": "merkle",
                    },
                    {
                        "provider_id": paired_id,
                        "provider_family": paired_family,
                    },
                ],
                "verified_operator_families": ["merkle", paired_family],
                "errors": [],
            }
        )
        trace_targets["targets"].append(
            {
                "target_id": f"trace-{index}",
                "case_id": f"case-{index}",
                "chain": chain,
                "chain_address": f"{chain}:0x{'1' * 40}",
                "calls": [
                    {
                        "provider_id": legacy_id,
                        "operator_family": "merkle",
                        "method": "trace_transaction",
                        "params": [f"0x{'a' * 64}"],
                    },
                    {
                        "provider_id": paired_id,
                        "operator_family": paired_family,
                        "method": "trace_transaction",
                        "params": [f"0x{'a' * 64}"],
                    },
                ],
            }
        )
        fragment_rows.append(
            {
                "provider_id": legacy_id,
                "chain": chain,
                "endpoint": LEGACY_ENDPOINTS[chain],
                "endpoint_template_sha256": hashlib.sha256(
                    LEGACY_ENDPOINTS[chain].encode("utf-8")
                ).hexdigest(),
                "operator_family": "merkle",
                "operator_identity_family": "merkle_blink",
                "operator_verified": True,
                "identity_scope": "LOCAL_TEST_LEGACY_ALIAS_ONLY",
                "review_expires_utc": "2026-08-30T12:00:00Z",
                "rpc_authorized": False,
            }
        )
        identity_chains.append(
            {
                "chain": chain,
                "complete": True,
                "errors": [],
                "provider_count": 2,
                "providers": [
                    {
                        "provider_id": legacy_id,
                        "verified_operator_family": "merkle",
                        "complete": True,
                    },
                    {
                        "provider_id": paired_id,
                        "verified_operator_family": paired_family,
                        "complete": True,
                    },
                ],
                "verified_operator_families": ["merkle", paired_family],
            }
        )
        registry_rows.extend(
            [
                {
                    "provider_id": legacy_id,
                    "chain": chain,
                    "endpoint": LEGACY_ENDPOINTS[chain],
                    "operator_family": "merkle",
                    "discovery_source": "synthetic-unverified",
                    "tracking_enabled": True,
                    "operator_evidence_url": None,
                    "operator_evidence_sha256": None,
                    "operator_verified": False,
                },
                {
                    "provider_id": paired_id,
                    "chain": chain,
                    "endpoint": f"https://{paired_id}.example/rpc",
                    "operator_family": paired_family,
                    "discovery_source": f"https://{paired_family}.example/docs",
                    "tracking_enabled": True,
                    "operator_evidence_url": f"https://{paired_family}.example/about",
                    "operator_evidence_sha256": f"{index}" * 64,
                    "operator_verified": True,
                },
            ]
        )
    capability["report_sha256"] = _canonical_sha(capability)
    capability_path = _write_json(tmp_path / "capability.json", capability)
    trace_targets["capability_report_file_sha256"] = hashlib.sha256(
        capability_path.read_bytes()
    ).hexdigest()
    trace_targets["capability_report_sha256"] = capability["report_sha256"]
    trace_targets["trace_targets_sha256"] = _canonical_sha(trace_targets)
    trace_path = _write_json(tmp_path / "trace-targets.json", trace_targets)

    verification: dict[str, object] = {
        "schema_version": "chronosaudit.control_provider_identity_legacy_alias_revision_approval_verification.v1",
        "decision": "LEGACY_ALIAS_PROVIDER_IDENTITY_REVISION_VERIFIED_LOCAL_TEST_ONLY",
        "revision_request_sha256": revision_sha,
        "reviewer_principal": "test-reviewer",
        "review_expires_utc": "2026-08-30T12:00:00Z",
        "target_identities_sha256": target_identities_sha,
        "trace_targets_sha256": trace_targets["trace_targets_sha256"],
        "provider_identity_revision_authorized": True,
        "provider_identity_verified": True,
        "provider_registry_fragment_verified": True,
        **FALSE_AUTHORITY,
    }
    verification["verification_sha256"] = _canonical_sha(verification)
    fragment: dict[str, object] = {
        "schema_version": "chronosaudit.control_provider_identity_legacy_alias_registry_fragment.v1",
        "decision": "LEGACY_ALIAS_REGISTRY_FRAGMENT_VERIFIED_LOCAL_TEST_ONLY",
        "revision_request_sha256": revision_sha,
        "reviewer_principal": "test-reviewer",
        "review_expires_utc": "2026-08-30T12:00:00Z",
        "provider_count": 3,
        "providers": fragment_rows,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
    }
    fragment["fragment_sha256"] = _canonical_sha(fragment)
    identity: dict[str, object] = {
        "schema_version": "chronosaudit.control_provider_identity_legacy_alias_verification.v1",
        "decision": "LEGACY_ALIAS_PROVIDER_IDENTITY_VERIFIED_LOCAL_TEST_ONLY",
        "revision_request_sha256": revision_sha,
        "chain_count": 3,
        "chains": identity_chains,
        "complete": True,
        "errors": [],
        "provider_identity_verified": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "counter_authority": False,
    }
    identity["report_sha256"] = _canonical_sha(identity)
    registry_path = tmp_path / "candidate-registry.yaml"
    registry_path.write_text(
        yaml.safe_dump({"version": "synthetic", "providers": registry_rows}),
        encoding="utf-8",
    )
    return {
        "verification": _write_json(tmp_path / "verification.json", verification),
        "fragment": _write_json(tmp_path / "fragment.json", fragment),
        "identity": _write_json(tmp_path / "identity.json", identity),
        "capability": capability_path,
        "trace": trace_path,
        "registry": registry_path,
    }


def test_projects_exact_six_provider_registry_without_rpc(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    result = build_legacy_alias_full_registry_projection(
        revision_verification_path=paths["verification"],
        registry_fragment_path=paths["fragment"],
        identity_report_path=paths["identity"],
        candidate_registry_path=paths["registry"],
        capability_report_path=paths["capability"],
        trace_targets_path=paths["trace"],
    )
    registry = result["provider_registry"]
    assert len(registry["providers"]) == 6
    assert all(row["operator_verified"] is True for row in registry["providers"])
    assert {
        row["operator_family"]
        for row in registry["providers"]
        if row["provider_id"].startswith("merkle-")
    } == {"merkle"}
    assert registry["projection_provenance"]["rpc_authorized"] is False
    verification = result["projection_verification"]
    assert verification["decision"] == (
        "LEGACY_ALIAS_FULL_PROVIDER_REGISTRY_PROJECTED_LOCAL_TEST_ONLY"
    )
    assert verification["provider_count"] == 6
    assert verification["provider_registry_verified"] is True
    assert verification["rpc_authorized"] is False
    assert verification["selection_authorized"] is False
    assert verification["counter_authority"] is False


def test_rejects_paired_family_and_trace_hash_drift(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    registry = yaml.safe_load(paths["registry"].read_text(encoding="utf-8"))
    next(
        row for row in registry["providers"] if row["provider_id"] == "drpc-base"
    )["operator_family"] = "substituted"
    paths["registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    with pytest.raises(
        ControlProviderIdentityLegacyAliasRegistryProjectionError,
        match="candidate_registry_provider_binding_mismatch",
    ):
        build_legacy_alias_full_registry_projection(
            revision_verification_path=paths["verification"],
            registry_fragment_path=paths["fragment"],
            identity_report_path=paths["identity"],
            candidate_registry_path=paths["registry"],
            capability_report_path=paths["capability"],
            trace_targets_path=paths["trace"],
        )

    paths = _inputs(tmp_path / "trace-drift")
    trace = json.loads(paths["trace"].read_text(encoding="utf-8"))
    trace["targets"][0]["calls"][0]["provider_id"] = "substituted"
    trace["trace_targets_sha256"] = _canonical_sha(
        {key: value for key, value in trace.items() if key != "trace_targets_sha256"}
    )
    _write_json(paths["trace"], trace)
    with pytest.raises(
        ControlProviderIdentityLegacyAliasRegistryProjectionError,
        match="trace_targets_revision_binding_mismatch",
    ):
        build_legacy_alias_full_registry_projection(
            revision_verification_path=paths["verification"],
            registry_fragment_path=paths["fragment"],
            identity_report_path=paths["identity"],
            candidate_registry_path=paths["registry"],
            capability_report_path=paths["capability"],
            trace_targets_path=paths["trace"],
        )


def test_projection_cli_writes_distinct_non_rpc_outputs(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    registry_output = tmp_path / "projected-registry.yaml"
    verification_output = tmp_path / "projection-verification.json"
    result = subprocess.run(
        [
            str(EXECUTABLE_ROOT / ".venv/bin/python"),
            str(
                EXECUTABLE_ROOT
                / "build_stage2_control_provider_identity_legacy_alias_registry_projection.py"
            ),
            "--revision-verification",
            str(paths["verification"]),
            "--registry-fragment",
            str(paths["fragment"]),
            "--identity-report",
            str(paths["identity"]),
            "--candidate-registry",
            str(paths["registry"]),
            "--capability-report",
            str(paths["capability"]),
            "--trace-targets",
            str(paths["trace"]),
            "--output-registry",
            str(registry_output),
            "--output-verification",
            str(verification_output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    registry = yaml.safe_load(registry_output.read_text(encoding="utf-8"))
    verification = json.loads(verification_output.read_text(encoding="utf-8"))
    assert len(registry["providers"]) == 6
    assert verification["provider_registry_verified"] is True
    assert verification["rpc_authorized"] is False
