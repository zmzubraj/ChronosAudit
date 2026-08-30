from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from chronosaudit_stage2.public_acquisition.control_provider_identity_evidence import (
    ControlProviderIdentityEvidenceError,
    build_control_provider_identity_evidence_review,
    verify_control_provider_identity_evidence_review,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(tmp_path: Path) -> dict[str, Path]:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    publicnode = evidence_root / "publicnode.html"
    one_rpc = evidence_root / "one-rpc.html"
    publicnode.write_text(
        "official endpoint https://ethereum-rpc.publicnode.com", encoding="utf-8"
    )
    one_rpc.write_text(
        "official endpoint https://public.1rpc.io/eth", encoding="utf-8"
    )
    registry = tmp_path / "providers.yaml"
    registry.write_text(
        yaml.safe_dump(
            {
                "version": "test",
                "providers": [
                    {
                        "provider_id": "publicnode-ethereum",
                        "chain": "ethereum",
                        "endpoint": "https://ethereum-rpc.publicnode.com",
                        "operator_family": "publicnode",
                        "discovery_source": "https://ethereum.publicnode.com/",
                        "tracking_enabled": True,
                        "operator_evidence_url": None,
                        "operator_evidence_sha256": None,
                        "operator_verified": False,
                    },
                    {
                        "provider_id": "one-rpc-ethereum",
                        "chain": "ethereum",
                        "endpoint": "https://public.1rpc.io/eth",
                        "operator_family": "1rpc",
                        "discovery_source": "https://docs.1rpc.io/using-the-web3-api/networks",
                        "tracking_enabled": True,
                        "operator_evidence_url": None,
                        "operator_evidence_sha256": None,
                        "operator_verified": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    index = tmp_path / "capture-index.json"
    index.write_text(
        json.dumps(
            {
                "schema_version": "chronosaudit.control_provider_document_capture_index.v1",
                "captures": [
                    {
                        "source_id": "publicnode-ethereum-doc",
                        "source_url": "https://ethereum.publicnode.com/",
                        "final_url": "https://ethereum.publicnode.com/",
                        "captured_path": "publicnode.html",
                        "captured_at_utc": "2026-08-20T00:00:00Z",
                        "http_status": 200,
                        "content_sha256": _sha(publicnode),
                        "operator_family": "publicnode",
                        "supported_provider_ids": ["publicnode-ethereum"],
                    },
                    {
                        "source_id": "one-rpc-networks-doc",
                        "source_url": "https://docs.1rpc.io/using-the-web3-api/networks",
                        "final_url": "https://docs.1rpc.io/using-the-web3-api/networks",
                        "captured_path": "one-rpc.html",
                        "captured_at_utc": "2026-08-20T00:00:00Z",
                        "http_status": 200,
                        "content_sha256": _sha(one_rpc),
                        "operator_family": "1rpc",
                        "supported_provider_ids": ["one-rpc-ethereum"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return {"registry": registry, "index": index, "evidence_root": evidence_root}


def _build(paths: dict[str, Path]) -> dict[str, object]:
    return build_control_provider_identity_evidence_review(
        provider_registry_path=paths["registry"],
        capture_index_path=paths["index"],
        evidence_root=paths["evidence_root"],
    )


def test_review_is_deterministic_complete_and_non_authorizing(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    review = _build(paths)

    assert review == _build(paths)
    assert review["decision"] == "EVIDENCE_CAPTURED_AWAITING_ACCOUNTABLE_PROVIDER_IDENTITY_REVIEW"
    assert review["provider_count"] == 2
    assert review["provider_ids"] == ["one-rpc-ethereum", "publicnode-ethereum"]
    assert review["provider_identity_verified"] is False
    assert review["reviewer_signature_required"] is True
    for field in (
        "operator_verified",
        "rpc_authorized",
        "selection_authorized",
        "stage_promotion_authorized",
        "recovery3_mutation_authorized",
    ):
        assert review[field] is False


def test_verifier_accepts_persisted_review(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(_build(paths), sort_keys=True), encoding="utf-8")
    result = verify_control_provider_identity_evidence_review(
        review_path=review_path,
        provider_registry_path=paths["registry"],
        capture_index_path=paths["index"],
        evidence_root=paths["evidence_root"],
    )
    assert result["decision"] == "PROVIDER_IDENTITY_EVIDENCE_REVIEW_VERIFIED_NON_AUTHORIZING"
    assert result["review_sha256"] == _sha(review_path)


def test_rejects_tampered_evidence(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    (paths["evidence_root"] / "publicnode.html").write_text("tampered", encoding="utf-8")
    with pytest.raises(ControlProviderIdentityEvidenceError, match="capture_content_sha256_mismatch"):
        _build(paths)


def test_rejects_capture_path_escape(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    outside = tmp_path / "outside.html"
    outside.write_text("https://ethereum-rpc.publicnode.com", encoding="utf-8")
    index = json.loads(paths["index"].read_text())
    index["captures"][0]["captured_path"] = "../outside.html"
    index["captures"][0]["content_sha256"] = _sha(outside)
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ControlProviderIdentityEvidenceError, match="capture_path_outside_evidence_root"):
        _build(paths)


def test_rejects_missing_endpoint_literal(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    capture = paths["evidence_root"] / "publicnode.html"
    capture.write_text("official page without endpoint", encoding="utf-8")
    index = json.loads(paths["index"].read_text())
    index["captures"][0]["content_sha256"] = _sha(capture)
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ControlProviderIdentityEvidenceError, match="provider_endpoint_not_in_capture"):
        _build(paths)


def test_rejects_operator_family_mismatch(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    index = json.loads(paths["index"].read_text())
    index["captures"][0]["operator_family"] = "1rpc"
    index["captures"][0]["source_url"] = "https://docs.1rpc.io/using-the-web3-api/networks"
    index["captures"][0]["final_url"] = "https://docs.1rpc.io/using-the-web3-api/networks"
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ControlProviderIdentityEvidenceError, match="provider_operator_family_mismatch"):
        _build(paths)


def test_accepts_official_base_operator_evidence(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    base_capture = paths["evidence_root"] / "base.html"
    base_capture.write_text(
        "official endpoint https://mainnet.base.org", encoding="utf-8"
    )
    registry = yaml.safe_load(paths["registry"].read_text(encoding="utf-8"))
    registry["providers"].append(
        {
            "provider_id": "base-official-base",
            "chain": "base",
            "endpoint": "https://mainnet.base.org",
            "operator_family": "base-official",
            "discovery_source": "https://docs.base.org/base-chain/api-reference/rpc-overview",
            "tracking_enabled": True,
            "operator_evidence_url": None,
            "operator_evidence_sha256": None,
            "operator_verified": False,
        }
    )
    paths["registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    index = json.loads(paths["index"].read_text(encoding="utf-8"))
    index["captures"].append(
        {
            "source_id": "base-official-rpc-doc",
            "source_url": "https://docs.base.org/base-chain/api-reference/rpc-overview",
            "final_url": "https://docs.base.org/base-chain/api-reference/rpc-overview",
            "captured_path": "base.html",
            "captured_at_utc": "2026-08-20T00:00:00Z",
            "http_status": 200,
            "content_sha256": _sha(base_capture),
            "operator_family": "base-official",
            "supported_provider_ids": ["base-official-base"],
        }
    )
    paths["index"].write_text(json.dumps(index), encoding="utf-8")

    review = _build(paths)

    assert review["provider_count"] == 3
    assert "base-official-base" in review["provider_ids"]


def test_accepts_official_nodereal_operator_evidence(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    nodereal_capture = paths["evidence_root"] / "nodereal.html"
    endpoint = "https://bsc-mainnet.nodereal.io/v1/public-example"
    nodereal_capture.write_text(f"official endpoint {endpoint}", encoding="utf-8")
    registry = yaml.safe_load(paths["registry"].read_text(encoding="utf-8"))
    registry["providers"].append(
        {
            "provider_id": "nodereal-bsc",
            "chain": "bsc",
            "endpoint": endpoint,
            "operator_family": "nodereal",
            "discovery_source": "https://docs.nodereal.io/reference/getting-started-with-your-api",
            "tracking_enabled": True,
            "operator_evidence_url": None,
            "operator_evidence_sha256": None,
            "operator_verified": False,
        }
    )
    paths["registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    index = json.loads(paths["index"].read_text(encoding="utf-8"))
    index["captures"].append(
        {
            "source_id": "nodereal-api-overview-doc",
            "source_url": "https://docs.nodereal.io/reference/getting-started-with-your-api",
            "final_url": "https://docs.nodereal.io/reference/getting-started-with-your-api",
            "captured_path": "nodereal.html",
            "captured_at_utc": "2026-08-20T00:00:00Z",
            "http_status": 200,
            "content_sha256": _sha(nodereal_capture),
            "operator_family": "nodereal",
            "supported_provider_ids": ["nodereal-bsc"],
        }
    )
    paths["index"].write_text(json.dumps(index), encoding="utf-8")

    review = _build(paths)

    assert review["provider_count"] == 3
    assert "nodereal-bsc" in review["provider_ids"]


def test_accepts_official_tenderly_operator_evidence(tmp_path: Path) -> None:
    paths = _inputs(tmp_path)
    tenderly_capture = paths["evidence_root"] / "tenderly.html"
    endpoint = "https://base.gateway.tenderly.co"
    tenderly_capture.write_text(f"official endpoint {endpoint}", encoding="utf-8")
    registry = yaml.safe_load(paths["registry"].read_text(encoding="utf-8"))
    registry["providers"].append(
        {
            "provider_id": "tenderly-base",
            "chain": "base",
            "endpoint": endpoint,
            "operator_family": "tenderly",
            "discovery_source": "https://tenderly.co/blog/changelog/base-mainnet",
            "tracking_enabled": True,
            "operator_evidence_url": None,
            "operator_evidence_sha256": None,
            "operator_verified": False,
        }
    )
    paths["registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    index = json.loads(paths["index"].read_text(encoding="utf-8"))
    index["captures"].append(
        {
            "source_id": "tenderly-base-production-node-doc",
            "source_url": "https://tenderly.co/blog/changelog/base-mainnet",
            "final_url": "https://tenderly.co/blog/changelog/base-mainnet",
            "captured_path": "tenderly.html",
            "captured_at_utc": "2026-08-21T00:00:00Z",
            "http_status": 200,
            "content_sha256": _sha(tenderly_capture),
            "operator_family": "tenderly",
            "supported_provider_ids": ["tenderly-base"],
        }
    )
    paths["index"].write_text(json.dumps(index), encoding="utf-8")

    review = _build(paths)

    assert review["provider_count"] == 3
    assert "tenderly-base" in review["provider_ids"]


@pytest.mark.parametrize(
    ("provider_id", "chain", "endpoint", "operator_family", "source_url"),
    [
        (
            "onfinality-bsc",
            "bsc",
            "https://bnb.api.onfinality.io/public",
            "onfinality",
            "https://onfinality.io/en/networks/bnb-chain",
        ),
        (
            "solidrpc-arbitrum",
            "arbitrum",
            "https://rpc.solidrpc.io/public/evm/42161",
            "solidrpc",
            "https://solidrpc.io/docs/public-rpc",
        ),
    ],
)
def test_accepts_current_official_public_provider_evidence(
    tmp_path: Path,
    provider_id: str,
    chain: str,
    endpoint: str,
    operator_family: str,
    source_url: str,
) -> None:
    paths = _inputs(tmp_path)
    capture = paths["evidence_root"] / f"{operator_family}.html"
    capture.write_text(f"official endpoint {endpoint}", encoding="utf-8")
    registry = yaml.safe_load(paths["registry"].read_text(encoding="utf-8"))
    registry["providers"].append(
        {
            "provider_id": provider_id,
            "chain": chain,
            "endpoint": endpoint,
            "operator_family": operator_family,
            "discovery_source": source_url,
            "tracking_enabled": True,
            "operator_evidence_url": source_url,
            "operator_evidence_sha256": None,
            "operator_verified": False,
        }
    )
    paths["registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    index = json.loads(paths["index"].read_text(encoding="utf-8"))
    index["captures"].append(
        {
            "source_id": f"{provider_id}-official-doc",
            "source_url": source_url,
            "final_url": source_url,
            "captured_path": capture.name,
            "captured_at_utc": "2026-08-22T00:00:00Z",
            "http_status": 200,
            "content_sha256": _sha(capture),
            "operator_family": operator_family,
            "supported_provider_ids": [provider_id],
        }
    )
    paths["index"].write_text(json.dumps(index), encoding="utf-8")

    review = _build(paths)

    assert provider_id in review["provider_ids"]


def test_accepts_official_quicknode_full_url_environment_binding(
    tmp_path: Path,
) -> None:
    paths = _inputs(tmp_path)
    quicknode_capture = paths["evidence_root"] / "quicknode.html"
    endpoint = "https://quiknode.pro/"
    quicknode_capture.write_text(
        "official Ethereum endpoint format "
        "https://your-endpoint.quiknode.pro/auth-token/",
        encoding="utf-8",
    )
    registry = yaml.safe_load(paths["registry"].read_text(encoding="utf-8"))
    registry["providers"].append(
        {
            "provider_id": "quicknode-ethereum",
            "chain": "ethereum",
            "endpoint": endpoint,
            "endpoint_env": "CHRONOS_QUICKNODE_ETHEREUM_URL",
            "operator_family": "quicknode",
            "discovery_source": "https://www.quicknode.com/docs/ethereum/endpoints",
            "tracking_enabled": True,
            "operator_evidence_url": None,
            "operator_evidence_sha256": None,
            "operator_verified": False,
        }
    )
    paths["registry"].write_text(yaml.safe_dump(registry), encoding="utf-8")
    index = json.loads(paths["index"].read_text(encoding="utf-8"))
    index["captures"].append(
        {
            "source_id": "quicknode-ethereum-endpoints-doc",
            "source_url": "https://www.quicknode.com/docs/ethereum/endpoints",
            "final_url": "https://www.quicknode.com/docs/ethereum/endpoints",
            "captured_path": "quicknode.html",
            "captured_at_utc": "2026-08-21T00:00:00Z",
            "http_status": 200,
            "content_sha256": _sha(quicknode_capture),
            "operator_family": "quicknode",
            "supported_provider_ids": ["quicknode-ethereum"],
        }
    )
    paths["index"].write_text(json.dumps(index), encoding="utf-8")

    review = _build(paths)

    quicknode = next(
        row for row in review["providers"]
        if row["provider_id"] == "quicknode-ethereum"
    )
    assert quicknode["endpoint_env"] == "CHRONOS_QUICKNODE_ETHEREUM_URL"
    assert quicknode["public_endpoint"] == endpoint
