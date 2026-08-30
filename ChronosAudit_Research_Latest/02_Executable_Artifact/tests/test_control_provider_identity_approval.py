from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from chronosaudit_stage2.public_acquisition.control_candidate_rpc_activation import (
    assess_control_candidate_rpc_provider_readiness,
)
from chronosaudit_stage2.public_acquisition.control_provider_identity_approval import (
    ControlProviderIdentityApprovalError,
    build_control_provider_identity_approval,
    build_control_provider_identity_approval_request,
    canonical_signed_payload,
    _project_registry,
    verify_control_provider_identity_approval,
)
from chronosaudit_stage2.public_acquisition.control_provider_identity_evidence import (
    build_control_provider_identity_evidence_review,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(tmp_path: Path) -> dict[str, Path]:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    publicnode = evidence_root / "publicnode.html"
    one_rpc = evidence_root / "one-rpc.html"
    publicnode_endpoints = {
        "ethereum": "https://ethereum-rpc.publicnode.com",
        "bsc": "https://bsc-rpc.publicnode.com",
        "base": "https://base-rpc.publicnode.com",
        "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
    }
    one_rpc_endpoints = {
        "ethereum": "https://public.1rpc.io/eth",
        "bsc": "https://public.1rpc.io/bnb",
        "base": "https://public.1rpc.io/base",
        "arbitrum": "https://public.1rpc.io/arb",
    }
    publicnode.write_text("\n".join(publicnode_endpoints.values()), encoding="utf-8")
    one_rpc.write_text("\n".join(one_rpc_endpoints.values()), encoding="utf-8")
    providers = []
    for chain in ("ethereum", "bsc", "base", "arbitrum"):
        for family, endpoint, source in (
            (
                "publicnode",
                publicnode_endpoints[chain],
                "https://ethereum.publicnode.com/",
            ),
            (
                "1rpc",
                one_rpc_endpoints[chain],
                "https://docs.1rpc.io/using-the-web3-api/networks",
            ),
        ):
            providers.append(
                {
                    "provider_id": f"{'one-rpc' if family == '1rpc' else family}-{chain}",
                    "chain": chain,
                    "endpoint": endpoint,
                    "operator_family": family,
                    "discovery_source": source,
                    "tracking_enabled": True,
                    "operator_evidence_url": None,
                    "operator_evidence_sha256": None,
                    "operator_verified": False,
                }
            )
    registry = tmp_path / "providers.yaml"
    registry.write_text(
        yaml.safe_dump({"version": "test", "providers": providers}), encoding="utf-8"
    )
    index = tmp_path / "capture-index.json"
    index.write_text(
        json.dumps(
            {
                "schema_version": "chronosaudit.control_provider_document_capture_index.v1",
                "captures": [
                    {
                        "source_id": "publicnode-doc",
                        "source_url": "https://ethereum.publicnode.com/",
                        "final_url": "https://ethereum.publicnode.com/",
                        "captured_path": "publicnode.html",
                        "captured_at_utc": "2026-08-20T00:00:00Z",
                        "http_status": 200,
                        "content_sha256": _sha(publicnode),
                        "operator_family": "publicnode",
                        "supported_provider_ids": [
                            f"publicnode-{chain}"
                            for chain in ("ethereum", "bsc", "base", "arbitrum")
                        ],
                    },
                    {
                        "source_id": "one-rpc-doc",
                        "source_url": "https://docs.1rpc.io/using-the-web3-api/networks",
                        "final_url": "https://docs.1rpc.io/using-the-web3-api/networks",
                        "captured_path": "one-rpc.html",
                        "captured_at_utc": "2026-08-20T00:00:00Z",
                        "http_status": 200,
                        "content_sha256": _sha(one_rpc),
                        "operator_family": "1rpc",
                        "supported_provider_ids": [
                            f"one-rpc-{chain}"
                            for chain in ("ethereum", "bsc", "base", "arbitrum")
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    review = tmp_path / "review.json"
    review.write_text(
        json.dumps(
            build_control_provider_identity_evidence_review(
                provider_registry_path=registry,
                capture_index_path=index,
                evidence_root=evidence_root,
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return {
        "registry": registry,
        "index": index,
        "evidence_root": evidence_root,
        "review": review,
    }


def _request(paths: dict[str, Path]) -> dict[str, object]:
    return build_control_provider_identity_approval_request(
        review_path=paths["review"],
        provider_registry_path=paths["registry"],
        capture_index_path=paths["index"],
        evidence_root=paths["evidence_root"],
    )


def _approval(request: dict[str, object]) -> dict[str, object]:
    return build_control_provider_identity_approval(
        request=request,
        reviewer_principal="provider-reviewer@example.org",
        review_start_utc="2026-08-20T01:00:00Z",
        review_expires_utc="2026-08-21T01:00:00Z",
    )


def _sign(tmp_path: Path, approval: dict[str, object]) -> tuple[Path, Path, Path]:
    key = tmp_path / "review-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    message = tmp_path / "review-message.json"
    message.write_bytes(canonical_signed_payload(approval))
    subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-q",
            "-f",
            str(key),
            "-n",
            "chronosaudit-stage2-control-provider-identity-review-v1",
            str(message),
        ],
        check=True,
    )
    signature = Path(f"{message}.sig")
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(
        "provider-reviewer@example.org "
        + Path(f"{key}.pub").read_text(encoding="utf-8").strip()
        + "\n",
        encoding="utf-8",
    )
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    return approval_path, signature, allowed


def test_request_and_unsigned_approval_are_deterministic_and_non_rpc(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    assert request == _request(paths)
    assert request["decision"] == "AWAITING_ACCOUNTABLE_PROVIDER_IDENTITY_SIGNATURE"
    assert request["provider_count"] == 8
    assert request["operator_families"] == ["1rpc", "publicnode"]
    assert request["rpc_authorized"] is False
    assert request["selection_authorized"] is False

    approval = _approval(request)
    assert approval == _approval(request)
    assert approval["decision"] == "APPROVE_CONTROL_PROVIDER_IDENTITY_BINDINGS"
    assert approval["registry_projection_authorized"] is True
    assert approval["identity_report_projection_authorized"] is True
    assert approval["rpc_authorized"] is False
    assert approval["selection_authorized"] is False


def test_registry_projection_preserves_runtime_only_api_key_environment_binding() -> None:
    binding = {
        "provider_id": "alchemy-base",
        "chain": "base",
        "endpoint": "https://base-mainnet.g.alchemy.com/v2/{api_key}",
        "api_key_env": "CHRONOS_ALCHEMY_API_KEY",
        "operator_family": "alchemy",
        "operator_evidence_url": "https://www.alchemy.com/docs/reference/node-supported-chains",
        "operator_evidence_sha256": "a" * 64,
    }
    request = {
        "request_sha256": "b" * 64,
        "review_payload_sha256": "c" * 64,
        "provider_bindings": [binding],
    }
    approval = {
        "reviewer_principal": "local-test",
        "review_expires_utc": "2026-08-28T00:00:00Z",
    }

    projected = _project_registry(request, approval)

    assert projected["providers"][0]["api_key_env"] == "CHRONOS_ALCHEMY_API_KEY"
    assert projected["providers"][0]["endpoint"] == binding["endpoint"]
    assert "secret" not in json.dumps(projected).lower()


def test_registry_projection_preserves_runtime_only_full_url_environment_binding() -> None:
    binding = {
        "provider_id": "quicknode-ethereum",
        "chain": "ethereum",
        "endpoint": "https://ethereum-mainnet.quiknode.pro/",
        "endpoint_env": "CHRONOS_QUICKNODE_ETHEREUM_URL",
        "operator_family": "quicknode",
        "operator_evidence_url": "https://www.quicknode.com/docs/ethereum/endpoints",
        "operator_evidence_sha256": "a" * 64,
    }
    request = {
        "request_sha256": "b" * 64,
        "review_payload_sha256": "c" * 64,
        "provider_bindings": [binding],
    }
    approval = {
        "reviewer_principal": "local-test",
        "review_expires_utc": "2026-08-28T00:00:00Z",
    }

    projected = _project_registry(request, approval)

    assert projected["providers"][0]["endpoint_env"] == (
        "CHRONOS_QUICKNODE_ETHEREUM_URL"
    )
    assert projected["providers"][0]["endpoint"] == binding["endpoint"]


def test_request_accepts_a_distinct_official_family_for_one_chain(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    base_capture = paths["evidence_root"] / "base.html"
    base_capture.write_text("https://mainnet.base.org", encoding="utf-8")
    registry = yaml.safe_load(paths["registry"].read_text(encoding="utf-8"))
    for provider in registry["providers"]:
        if provider["provider_id"] == "one-rpc-base":
            provider.update(
                {
                    "provider_id": "base-official-base",
                    "endpoint": "https://mainnet.base.org",
                    "operator_family": "base-official",
                    "discovery_source": "https://docs.base.org/base-chain/quickstart/connecting-to-base",
                }
            )
    paths["registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    index = json.loads(paths["index"].read_text(encoding="utf-8"))
    index["captures"][1]["supported_provider_ids"].remove("one-rpc-base")
    index["captures"].append(
        {
            "source_id": "base-official-doc",
            "source_url": "https://docs.base.org/base-chain/quickstart/connecting-to-base",
            "final_url": "https://docs.base.org/base-chain/quickstart/connecting-to-base",
            "captured_path": "base.html",
            "captured_at_utc": "2026-08-20T00:00:00Z",
            "http_status": 200,
            "content_sha256": _sha(base_capture),
            "operator_family": "base-official",
            "supported_provider_ids": ["base-official-base"],
        }
    )
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    paths["review"].write_text(
        json.dumps(
            build_control_provider_identity_evidence_review(
                provider_registry_path=paths["registry"],
                capture_index_path=paths["index"],
                evidence_root=paths["evidence_root"],
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    request = _request(paths)

    assert request["operator_families"] == ["1rpc", "base-official", "publicnode"]
    assert request["required_independence_attestation"] == (
        "AT_LEAST_TWO_DISTINCT_VERIFIED_OPERATOR_FAMILIES_PER_CHAIN"
    )


def test_valid_signature_projects_matching_registry_and_identity_report(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    original_registry_sha = _sha(paths["registry"])
    request = _request(paths)
    approval_path, signature, allowed = _sign(tmp_path, _approval(request))

    result = verify_control_provider_identity_approval(
        request=request,
        approval_path=approval_path,
        signature_path=signature,
        allowed_signers_path=allowed,
        expected_principal="provider-reviewer@example.org",
        verification_time_utc="2026-08-20T12:00:00Z",
    )

    assert result["verification"]["decision"] == "PROVIDER_IDENTITY_APPROVAL_VERIFIED"
    assert result["verification"]["rpc_authorized"] is False
    assert result["verification"]["selection_authorized"] is False
    assert all(
        provider["operator_verified"] is True
        for provider in result["provider_registry_projection"]["providers"]
    )
    assert result["provider_identity_verification"]["complete"] is True
    assert result["provider_identity_verification"]["chain_count"] == 4
    assert _sha(paths["registry"]) == original_registry_sha

    projected_registry = tmp_path / "projected-registry.yaml"
    projected_identity = tmp_path / "projected-identity.json"
    projected_registry.write_text(
        yaml.safe_dump(result["provider_registry_projection"], sort_keys=False),
        encoding="utf-8",
    )
    projected_identity.write_text(
        json.dumps(result["provider_identity_verification"], sort_keys=True),
        encoding="utf-8",
    )
    readiness = assess_control_candidate_rpc_provider_readiness(
        provider_registry_path=projected_registry,
        provider_identity_verification_path=projected_identity,
        required_chains=["ethereum", "bsc", "base", "arbitrum"],
    )
    assert readiness["decision"] == "RPC_PROVIDER_IDENTITY_READY_NON_AUTHORIZING"
    assert readiness["blockers"] == []
    assert readiness["rpc_authorized"] is False


def test_rejects_tampered_or_expired_signed_approval(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    approval = _approval(request)
    approval_path, signature, allowed = _sign(tmp_path, approval)
    tampered = dict(approval)
    tampered["rpc_authorized"] = True
    approval_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ControlProviderIdentityApprovalError, match="approval_rpc_authorized_invalid"):
        verify_control_provider_identity_approval(
            request=request,
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="provider-reviewer@example.org",
            verification_time_utc="2026-08-20T12:00:00Z",
        )

    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    with pytest.raises(ControlProviderIdentityApprovalError, match="review_expired"):
        verify_control_provider_identity_approval(
            request=request,
            approval_path=approval_path,
            signature_path=signature,
            allowed_signers_path=allowed,
            expected_principal="provider-reviewer@example.org",
            verification_time_utc="2026-08-22T00:00:00Z",
        )


def test_unsigned_approval_builder_rejects_authorizing_request(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    request = _request(paths)
    request["rpc_authorized"] = True
    material = {key: value for key, value in request.items() if key != "request_sha256"}
    request["request_sha256"] = hashlib.sha256(
        json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(ControlProviderIdentityApprovalError, match="request_rpc_authorized_invalid"):
        _approval(request)
