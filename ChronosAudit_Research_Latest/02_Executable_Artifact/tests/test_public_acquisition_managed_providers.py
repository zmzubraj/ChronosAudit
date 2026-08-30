import urllib.error
from pathlib import Path

import pytest

from chronosaudit_stage2.onchain import ProviderObservation, provider_urls_from_env
from chronosaudit_stage2.public_acquisition.managed_providers import (
    ManagedProviderConfigurationError,
    ManagedProviderCredentialSource,
    load_managed_provider_templates,
    preflight_managed_provider,
    providers_for_chain_from_managed_env,
)
from chronosaudit_stage2.public_acquisition.providers import ProviderRegistry


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "config" / "managed_archive_provider_templates.yaml"


@pytest.mark.parametrize(
    ("chain", "alchemy_host", "infura_host"),
    [
        ("ethereum", "eth-mainnet.g.alchemy.com", "mainnet.infura.io"),
        ("bsc", "bnb-mainnet.g.alchemy.com", "bsc-mainnet.infura.io"),
        ("base", "base-mainnet.g.alchemy.com", "base-mainnet.infura.io"),
        ("arbitrum", "arb-mainnet.g.alchemy.com", "arbitrum-mainnet.infura.io"),
    ],
)
def test_managed_templates_expand_supported_network_hostnames(chain, alchemy_host, infura_host, tmp_path):
    registry = load_managed_provider_templates(TEMPLATES)

    providers = providers_for_chain_from_managed_env(
        chain,
        templates=registry,
        env={
            "CHRONOS_ALCHEMY_API_KEY": "alchemy-test-key",
            "CHRONOS_INFURA_API_KEY": "infura-test-key",
        },
        artifact_root=tmp_path,
        timeout=9,
        retries=1,
    )

    assert [(provider.provider_family, provider.url.split("/")[2]) for provider in providers] == [
        ("alchemy", alchemy_host),
        ("infura", infura_host),
    ]
    assert providers[0].url.endswith("/alchemy-test-key")
    assert providers[1].url.endswith("/infura-test-key")
    assert providers[0].timeout == 9
    assert providers[0].max_retries == 1


def test_managed_providers_bind_exact_family_and_non_secret_template_identity(tmp_path):
    registry = load_managed_provider_templates(TEMPLATES)
    providers = providers_for_chain_from_managed_env(
        "arbitrum",
        templates=registry,
        env={
            "CHRONOS_ALCHEMY_API_KEY": "secret-alchemy-value",
            "CHRONOS_INFURA_API_KEY": "secret-infura-value",
        },
        artifact_root=tmp_path,
        timeout=5,
        retries=0,
    )

    assert {provider.provider_family for provider in providers} == {"alchemy", "infura"}
    assert len({provider.provider_family for provider in providers}) == 2
    for provider in providers:
        evidence = provider.provider_identity_evidence
        assert evidence["operator_family"] == provider.provider_family
        assert evidence["chain"] == "arbitrum"
        assert len(evidence["endpoint_template_sha256"]) == 64
        serialized = repr(evidence)
        assert "secret-alchemy-value" not in serialized
        assert "secret-infura-value" not in serialized


@pytest.mark.parametrize("missing", ["CHRONOS_ALCHEMY_API_KEY", "CHRONOS_INFURA_API_KEY"])
def test_managed_provider_resolution_fails_closed_when_one_family_key_is_missing(missing, tmp_path):
    registry = load_managed_provider_templates(TEMPLATES)
    env = {
        "CHRONOS_ALCHEMY_API_KEY": "alchemy-test-key",
        "CHRONOS_INFURA_API_KEY": "infura-test-key",
    }
    env.pop(missing)

    with pytest.raises(ManagedProviderConfigurationError) as exc_info:
        providers_for_chain_from_managed_env(
            "ethereum",
            templates=registry,
            env=env,
            artifact_root=tmp_path,
            timeout=5,
            retries=0,
        )

    assert exc_info.value.code == "missing_api_key"
    assert missing in str(exc_info.value)


def test_managed_provider_resolution_rejects_unsupported_provider_chain_combination(tmp_path):
    registry = load_managed_provider_templates(TEMPLATES)

    with pytest.raises(ManagedProviderConfigurationError) as exc_info:
        providers_for_chain_from_managed_env(
            "optimism",
            templates=registry,
            env={
                "CHRONOS_ALCHEMY_API_KEY": "alchemy-test-key",
                "CHRONOS_INFURA_API_KEY": "infura-test-key",
            },
            artifact_root=tmp_path,
            timeout=5,
            retries=0,
        )

    assert exc_info.value.code == "unsupported_chain"


def test_managed_provider_resolution_rejects_supported_chain_missing_from_registry(tmp_path):
    from chronosaudit_stage2.public_acquisition.managed_providers import ManagedProviderTemplateRegistry

    registry = ManagedProviderTemplateRegistry.from_mapping(
        {
            "version": "1.0.0",
            "providers": [
                {
                    "provider_id": "only-ethereum",
                    "operator_family": "one-family",
                    "api_key_env": "CHRONOS_ONE_API_KEY",
                    "operator_evidence_url": "https://one.example/about",
                    "chains": {
                        "ethereum": {
                            "chain_id": "0x1",
                            "endpoint_template": "https://one.example/v1/{api_key}",
                        }
                    },
                }
            ],
        }
    )

    with pytest.raises(ManagedProviderConfigurationError) as exc_info:
        providers_for_chain_from_managed_env(
            "bsc",
            templates=registry,
            env={"CHRONOS_ONE_API_KEY": "test-key"},
            artifact_root=tmp_path,
        )

    assert exc_info.value.code == "unsupported_provider_chain_combination"


def test_managed_provider_errors_and_public_identity_never_contain_secret_values(tmp_path):
    registry = load_managed_provider_templates(TEMPLATES)
    alchemy_secret = "alchemy-secret-123"
    infura_secret = "infura-secret-456"
    providers = providers_for_chain_from_managed_env(
        "base",
        templates=registry,
        env={
            "CHRONOS_ALCHEMY_API_KEY": alchemy_secret,
            "CHRONOS_INFURA_API_KEY": infura_secret,
        },
        artifact_root=tmp_path,
        timeout=5,
        retries=0,
    )

    for provider in providers:
        evidence = provider.provider_identity_evidence
        assert alchemy_secret not in evidence["public_endpoint_template"]
        assert infura_secret not in evidence["public_endpoint_template"]
        assert alchemy_secret not in provider.public_endpoint
        assert infura_secret not in provider.public_endpoint


def test_managed_provider_resolution_reuses_api_key_from_authorized_source_urls(tmp_path):
    registry = load_managed_provider_templates(TEMPLATES)

    providers = providers_for_chain_from_managed_env(
        "ethereum",
        templates=registry,
        env={
            "CHRONOS_ALCHEMY_ARBITRUM_URL": "https://arb-mainnet.g.alchemy.com/v2/alchemy%2Fcredential",
            "CHRONOS_INFURA_ARBITRUM_URL": "https://arbitrum-mainnet.infura.io/v3/infura%2Bcredential",
        },
        artifact_root=tmp_path,
        timeout=7,
        retries=0,
    )

    assert [(provider.provider_family, provider.url.split("/")[2]) for provider in providers] == [
        ("alchemy", "eth-mainnet.g.alchemy.com"),
        ("infura", "mainnet.infura.io"),
    ]
    assert providers[0].url.endswith("/alchemy%2Fcredential")
    assert providers[1].url.endswith("/infura%2Bcredential")


def test_managed_provider_generic_api_keys_take_precedence_over_source_urls(tmp_path):
    registry = load_managed_provider_templates(TEMPLATES)

    providers = providers_for_chain_from_managed_env(
        "base",
        templates=registry,
        env={
            "CHRONOS_ALCHEMY_API_KEY": "direct-alchemy-key",
            "CHRONOS_INFURA_API_KEY": "direct-infura-key",
            "CHRONOS_ALCHEMY_ARBITRUM_URL": "https://arb-mainnet.g.alchemy.com/v2/unused-source-key",
            "CHRONOS_INFURA_ARBITRUM_URL": "https://arbitrum-mainnet.infura.io/v3/unused-source-key",
        },
        artifact_root=tmp_path,
        timeout=5,
        retries=0,
    )

    assert providers[0].url.endswith("/direct-alchemy-key")
    assert providers[1].url.endswith("/direct-infura-key")
    assert "unused-source-key" not in providers[0].url
    assert "unused-source-key" not in providers[1].url


@pytest.mark.parametrize(
    ("source_url", "secret"),
    [
        ("https://arbitrum-mainnet.infura.io/v3/wrong-operator-secret", "wrong-operator-secret"),
        ("https://arb-mainnet.g.alchemy.com/v2/?token=query-secret", "query-secret"),
        ("https://user:fragment-secret@arb-mainnet.g.alchemy.com/v2/token#fragment-secret", "fragment-secret"),
        ("https://arb-mainnet.g.alchemy.com/v2/", "missing-secret"),
        ("https://arb-mainnet.g.alchemy.com/v2/raw/slash", "raw/slash"),
        ("https://arb-mainnet.g.alchemy.com/v2/noncanonical%2fsecret", "noncanonical/secret"),
    ],
)
def test_managed_provider_resolution_rejects_invalid_authorized_source_url_without_secret_leak(
    source_url,
    secret,
    tmp_path,
):
    registry = load_managed_provider_templates(TEMPLATES)

    with pytest.raises(ManagedProviderConfigurationError) as exc_info:
        providers_for_chain_from_managed_env(
            "ethereum",
            templates=registry,
            env={
                "CHRONOS_ALCHEMY_ARBITRUM_URL": source_url,
                "CHRONOS_INFURA_ARBITRUM_URL": "https://arbitrum-mainnet.infura.io/v3/infura-source-key",
            },
            artifact_root=tmp_path,
            timeout=5,
            retries=0,
        )

    rendered = f"{exc_info.value!r} {exc_info.value}"
    assert exc_info.value.code == "invalid_api_key_source_url"
    assert "CHRONOS_ALCHEMY_ARBITRUM_URL" in rendered
    assert source_url not in rendered
    assert secret not in rendered


def test_managed_provider_resolution_rejects_duplicate_source_url_family_configuration(tmp_path):
    registry = load_managed_provider_templates(TEMPLATES)

    with pytest.raises(ManagedProviderConfigurationError) as exc_info:
        providers_for_chain_from_managed_env(
            "ethereum",
            templates=registry,
            env={
                "CHRONOS_ALCHEMY_PRIMARY_URL": "https://arb-mainnet.g.alchemy.com/v2/one",
                "CHRONOS_ALCHEMY_SECONDARY_URL": "https://arb-mainnet.g.alchemy.com/v2/two",
                "CHRONOS_INFURA_ARBITRUM_URL": "https://arbitrum-mainnet.infura.io/v3/infura-source-key",
            },
            artifact_root=tmp_path,
            credential_sources=(
                ManagedProviderCredentialSource("alchemy", "arbitrum", "CHRONOS_ALCHEMY_PRIMARY_URL"),
                ManagedProviderCredentialSource("alchemy", "arbitrum", "CHRONOS_ALCHEMY_SECONDARY_URL"),
                ManagedProviderCredentialSource("infura", "arbitrum", "CHRONOS_INFURA_ARBITRUM_URL"),
            ),
        )

    assert exc_info.value.code == "duplicate_credential_source_family"


def test_managed_provider_resolution_rejects_unsupported_source_url_chain_configuration(tmp_path):
    registry = load_managed_provider_templates(TEMPLATES)

    with pytest.raises(ManagedProviderConfigurationError) as exc_info:
        providers_for_chain_from_managed_env(
            "ethereum",
            templates=registry,
            env={"CHRONOS_ALCHEMY_OPTIMISM_URL": "https://opt-mainnet.g.alchemy.com/v2/source-key"},
            artifact_root=tmp_path,
            credential_sources=(ManagedProviderCredentialSource("alchemy", "optimism", "CHRONOS_ALCHEMY_OPTIMISM_URL"),),
        )

    assert exc_info.value.code == "unsupported_chain"


def test_managed_registry_rejects_duplicate_operator_family_for_chain():
    from chronosaudit_stage2.public_acquisition.managed_providers import ManagedProviderTemplateRegistry

    mapping = {
        "version": "1.0.0",
        "providers": [
            {
                "provider_id": "one",
                "operator_family": "same-family",
                "api_key_env": "CHRONOS_ONE_API_KEY",
                "operator_evidence_url": "https://one.example/about",
                "chains": {"ethereum": {"chain_id": "0x1", "endpoint_template": "https://one.example/v1/{api_key}"}},
            },
            {
                "provider_id": "two",
                "operator_family": "same-family",
                "api_key_env": "CHRONOS_TWO_API_KEY",
                "operator_evidence_url": "https://two.example/about",
                "chains": {"ethereum": {"chain_id": "0x1", "endpoint_template": "https://two.example/v1/{api_key}"}},
            },
        ],
    }

    with pytest.raises(ManagedProviderConfigurationError) as exc_info:
        ManagedProviderTemplateRegistry.from_mapping(mapping)

    assert exc_info.value.code == "duplicate_operator_family"


def test_explicit_url_environment_takes_precedence_over_managed_keys(tmp_path):
    registry = ProviderRegistry.from_mapping(
        {
            "providers": [
                {
                    "provider_id": "explicit-one",
                    "chain": "ethereum",
                    "endpoint": "https://rpc.example/one",
                    "operator_family": "family-one",
                    "operator_evidence_url": "https://family-one.example/about",
                    "operator_evidence_sha256": "1" * 64,
                    "operator_verified": True,
                },
                {
                    "provider_id": "explicit-two",
                    "chain": "ethereum",
                    "endpoint": "https://rpc.example/two",
                    "operator_family": "family-two",
                    "operator_evidence_url": "https://family-two.example/about",
                    "operator_evidence_sha256": "2" * 64,
                    "operator_verified": True,
                },
            ]
        }
    )
    providers = provider_urls_from_env(
        "ethereum",
        registry=registry,
        env={
            "CHRONOS_ETHEREUM_ARCHIVE_RPC_URLS": "https://rpc.example/one,https://rpc.example/two",
            "CHRONOS_ETHEREUM_ARCHIVE_RPC_PROVIDER_FAMILIES": "family-one,family-two",
            "CHRONOS_ALCHEMY_API_KEY": "unused-alchemy-key",
            "CHRONOS_INFURA_API_KEY": "unused-infura-key",
        },
        artifact_root=tmp_path,
    )

    assert [provider.url for provider in providers] == ["https://rpc.example/one", "https://rpc.example/two"]
    assert [provider.provider_family for provider in providers] == ["family-one", "family-two"]


def test_explicit_url_environment_requires_matching_family_list(tmp_path):
    with pytest.raises(ManagedProviderConfigurationError) as exc_info:
        provider_urls_from_env(
            "ethereum",
            env={
                "CHRONOS_ETHEREUM_ARCHIVE_RPC_URLS": "https://rpc.example/one,https://rpc.example/two",
            },
            artifact_root=tmp_path,
        )

    assert exc_info.value.code == "missing_explicit_provider_families"


def test_explicit_url_environment_rejects_two_verified_endpoints_from_same_family(tmp_path):
    registry = ProviderRegistry.from_mapping(
        {
            "providers": [
                {
                    "provider_id": "same-family-one",
                    "chain": "ethereum",
                    "endpoint": "https://rpc.example/one",
                    "operator_family": "same-family",
                    "operator_evidence_url": "https://same-family.example/about",
                    "operator_evidence_sha256": "1" * 64,
                    "operator_verified": True,
                },
                {
                    "provider_id": "same-family-two",
                    "chain": "ethereum",
                    "endpoint": "https://rpc.example/two",
                    "operator_family": "same-family",
                    "operator_evidence_url": "https://same-family.example/about",
                    "operator_evidence_sha256": "2" * 64,
                    "operator_verified": True,
                },
            ]
        }
    )

    with pytest.raises(ManagedProviderConfigurationError) as exc_info:
        provider_urls_from_env(
            "ethereum",
            registry=registry,
            env={
                "CHRONOS_ETHEREUM_ARCHIVE_RPC_URLS": "https://rpc.example/one,https://rpc.example/two",
                "CHRONOS_ETHEREUM_ARCHIVE_RPC_PROVIDER_FAMILIES": "same-family,same-family",
            },
            artifact_root=tmp_path,
        )

    assert exc_info.value.code == "insufficient_independent_provider_families"


def test_provider_urls_from_env_uses_managed_templates_only_when_explicit_urls_absent(tmp_path):
    providers = provider_urls_from_env(
        "bsc",
        env={
            "CHRONOS_ALCHEMY_API_KEY": "alchemy-test-key",
            "CHRONOS_INFURA_API_KEY": "infura-test-key",
        },
        artifact_root=tmp_path,
    )

    assert [(provider.provider_family, provider.provider_id) for provider in providers] == [
        ("alchemy", "alchemy-bsc"),
        ("infura", "infura-bsc"),
    ]


def test_provider_urls_from_env_uses_managed_source_urls_when_api_keys_absent(tmp_path):
    providers = provider_urls_from_env(
        "bsc",
        env={
            "CHRONOS_ALCHEMY_ARBITRUM_URL": "https://arb-mainnet.g.alchemy.com/v2/alchemy%2Fsource-key",
            "CHRONOS_INFURA_ARBITRUM_URL": "https://arbitrum-mainnet.infura.io/v3/infura%2Fsource-key",
        },
        artifact_root=tmp_path,
    )

    assert [(provider.provider_family, provider.provider_id) for provider in providers] == [
        ("alchemy", "alchemy-bsc"),
        ("infura", "infura-bsc"),
    ]
    assert providers[0].url.endswith("/alchemy%2Fsource-key")
    assert providers[1].url.endswith("/infura%2Fsource-key")


def test_no_provider_configuration_still_returns_empty_for_public_fallback(tmp_path):
    assert provider_urls_from_env("ethereum", env={}, artifact_root=tmp_path) == []


def test_transport_error_redacts_managed_api_key(monkeypatch, tmp_path):
    secret = "secret-runtime-key-123"
    provider = providers_for_chain_from_managed_env(
        "ethereum",
        templates=load_managed_provider_templates(TEMPLATES),
        env={
            "CHRONOS_ALCHEMY_API_KEY": secret,
            "CHRONOS_INFURA_API_KEY": "other-runtime-key-456",
        },
        artifact_root=tmp_path,
        timeout=1,
        retries=0,
    )[0]

    def fail(*_args, **_kwargs):
        raise urllib.error.URLError(f"failed endpoint {provider.url}")

    monkeypatch.setattr("urllib.request.urlopen", fail)
    observation = provider.call("eth_chainId", [])

    assert secret not in (observation.error or "")
    assert "{api_key}" in (observation.error or "")


class FakePreflightProvider:
    def __init__(self, *, chain_id="0x1", fail_method=None):
        self.provider_id = "fake-managed"
        self.provider_family = "fake-family"
        self.provider_identity_evidence = {
            "provider_id": self.provider_id,
            "operator_family": self.provider_family,
            "chain": "ethereum",
            "expected_chain_id": "0x1",
            "operator_evidence_url": "https://fake.example/about",
            "public_endpoint_template": "https://fake.example/v1/{api_key}",
            "endpoint_template_sha256": "a" * 64,
        }
        self.chain_id = chain_id
        self.fail_method = fail_method

    def call(self, method, params):
        if method == self.fail_method:
            return ProviderObservation(
                self.provider_id,
                method,
                params,
                None,
                1,
                error="blocked",
                provider_family=self.provider_family,
                request_sha256="b" * 64,
                response_sha256="c" * 64,
                raw_response_path="receipts/cc.json",
                observed_at_utc="2026-08-09T00:00:00Z",
            )
        if method == "eth_chainId":
            result = self.chain_id
        elif method == "eth_getBlockByNumber":
            result = {"number": "0x10", "hash": "0x" + "ab" * 32}
        elif method == "eth_getCode":
            result = "0x6000"
        elif method == "eth_getStorageAt":
            result = "0x" + "00" * 32
        else:
            raise AssertionError(method)
        return ProviderObservation(
            self.provider_id,
            method,
            params,
            result,
            1,
            provider_family=self.provider_family,
            request_sha256="b" * 64,
            response_sha256="c" * 64,
            raw_response_path="receipts/cc.json",
            observed_at_utc="2026-08-09T00:00:00Z",
        )


def test_managed_preflight_requires_chain_and_historical_eip1898_reads():
    result = preflight_managed_provider(
        FakePreflightProvider(),
        historical_block_number=16,
        representative_address="0x" + "11" * 20,
    )

    assert result["status"] == "eligible"
    assert result["checks"] == {
        "chain_id": "pass",
        "historical_block": "pass",
        "eip1898_code": "pass",
        "eip1898_storage": "pass",
    }
    assert result["block_selector"] == {"blockHash": "0x" + "ab" * 32, "requireCanonical": True}


@pytest.mark.parametrize(
    ("provider", "blocker"),
    [
        (FakePreflightProvider(chain_id="0x38"), "chain_id_mismatch"),
        (FakePreflightProvider(fail_method="eth_getCode"), "eip1898_code_failed"),
        (FakePreflightProvider(fail_method="eth_getStorageAt"), "eip1898_storage_failed"),
    ],
)
def test_managed_preflight_fails_closed(provider, blocker):
    result = preflight_managed_provider(
        provider,
        historical_block_number=16,
        representative_address="0x" + "11" * 20,
    )

    assert result["status"] == "blocked"
    assert blocker in result["blockers"]
