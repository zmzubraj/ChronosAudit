from __future__ import annotations

import pytest

from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


def _record(
    *,
    endpoint: str,
    api_key_env: str | None = None,
    endpoint_env: str | None = None,
):
    provider = {
        "provider_id": "alchemy-base",
        "chain": "base",
        "endpoint": endpoint,
        "operator_family": "alchemy",
        "discovery_source": "local-test-managed-template",
        "tracking_enabled": True,
        "operator_evidence_url": "https://www.alchemy.com/",
        "operator_evidence_sha256": None,
        "operator_verified": True,
    }
    if api_key_env is not None:
        provider["api_key_env"] = api_key_env
    if endpoint_env is not None:
        provider["endpoint_env"] = endpoint_env
    return ProviderRegistry.from_mapping({"providers": [provider]}).providers[0]


def test_direct_endpoint_resolution_is_backward_compatible():
    record = _record(endpoint="https://base.example.invalid/rpc")

    assert record.resolved_endpoint({}) == "https://base.example.invalid/rpc"


def test_managed_endpoint_resolves_only_from_named_runtime_environment():
    record = _record(
        endpoint="https://base-mainnet.g.alchemy.com/v2/{api_key}",
        api_key_env="CHRONOS_ALCHEMY_API_KEY",
    )

    resolved = record.resolved_endpoint(
        {"CHRONOS_ALCHEMY_API_KEY": "local/test+credential"}
    )

    assert resolved.endswith("/local%2Ftest%2Bcredential")
    assert "local/test+credential" not in record.endpoint
    assert "local/test+credential" not in record.public_endpoint
    assert "local/test+credential" not in record.public_endpoint_id
    assert record.public_endpoint == record.endpoint


def test_managed_endpoint_missing_key_fails_closed_without_secret_leak():
    record = _record(
        endpoint="https://base-mainnet.g.alchemy.com/v2/{api_key}",
        api_key_env="CHRONOS_ALCHEMY_API_KEY",
    )

    with pytest.raises(ValueError) as exc_info:
        record.resolved_endpoint({"UNRELATED_SECRET": "must-not-leak"})

    rendered = f"{exc_info.value!r} {exc_info.value}"
    assert "CHRONOS_ALCHEMY_API_KEY" in rendered
    assert "must-not-leak" not in rendered


def test_full_url_environment_binding_resolves_without_persisting_secret_url():
    record = _record(
        endpoint="https://ethereum-mainnet.quiknode.pro/",
        endpoint_env="CHRONOS_QUICKNODE_ETHEREUM_URL",
    )

    secret_url = "https://private.ethereum-mainnet.quiknode.pro/secret-token/"
    resolved = record.resolved_endpoint(
        {"CHRONOS_QUICKNODE_ETHEREUM_URL": secret_url}
    )

    assert resolved == secret_url
    assert "private" not in record.endpoint
    assert "secret-token" not in record.endpoint
    assert record.public_endpoint == record.endpoint


@pytest.mark.parametrize(
    "secret_url",
    [
        "http://private.ethereum-mainnet.quiknode.pro/secret-token/",
        "https://attacker.example/secret-token/",
        "https://user:password@ethereum-mainnet.quiknode.pro/secret-token/",
    ],
)
def test_full_url_environment_binding_rejects_unsafe_runtime_url_without_leak(
    secret_url,
):
    record = _record(
        endpoint="https://ethereum-mainnet.quiknode.pro/",
        endpoint_env="CHRONOS_QUICKNODE_ETHEREUM_URL",
    )

    with pytest.raises(ValueError) as exc_info:
        record.resolved_endpoint(
            {"CHRONOS_QUICKNODE_ETHEREUM_URL": secret_url}
        )

    rendered = f"{exc_info.value!r} {exc_info.value}"
    assert secret_url not in rendered
    assert "secret-token" not in rendered


@pytest.mark.parametrize(
    ("endpoint", "api_key_env", "endpoint_env"),
    [
        (
            "https://ethereum-mainnet.quiknode.pro/",
            None,
            "QUICKNODE_ETHEREUM_URL",
        ),
        (
            "https://ethereum-mainnet.quiknode.pro/credential-like-path",
            None,
            "CHRONOS_QUICKNODE_ETHEREUM_URL",
        ),
        (
            "https://ethereum-mainnet.quiknode.pro/",
            "CHRONOS_QUICKNODE_API_KEY",
            "CHRONOS_QUICKNODE_ETHEREUM_URL",
        ),
    ],
)
def test_malformed_full_url_environment_binding_is_rejected(
    endpoint, api_key_env, endpoint_env
):
    with pytest.raises(ValueError):
        _record(
            endpoint=endpoint,
            api_key_env=api_key_env,
            endpoint_env=endpoint_env,
        )


@pytest.mark.parametrize(
    ("endpoint", "api_key_env"),
    [
        ("http://base.example.invalid/v2/{api_key}", "CHRONOS_ALCHEMY_API_KEY"),
        ("https://base.example.invalid/v2/{api_key}/{api_key}", "CHRONOS_ALCHEMY_API_KEY"),
        ("https://base.example.invalid/v2/{token}", "CHRONOS_ALCHEMY_API_KEY"),
        ("https://base.example.invalid/v2/{api_key}?x=1", "CHRONOS_ALCHEMY_API_KEY"),
        ("https://base.example.invalid/v2/{api_key}", "ALCHEMY_API_KEY"),
        ("https://base.example.invalid/rpc", "CHRONOS_ALCHEMY_API_KEY"),
    ],
)
def test_malformed_managed_endpoint_configuration_is_rejected(endpoint, api_key_env):
    with pytest.raises(ValueError):
        _record(endpoint=endpoint, api_key_env=api_key_env)
