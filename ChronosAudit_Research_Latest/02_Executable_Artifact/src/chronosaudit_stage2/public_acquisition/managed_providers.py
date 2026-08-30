from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import quote, unquote, urlsplit

import jsonschema
import yaml

from .model import SUPPORTED_CHAINS
from .providers import redact_endpoint


_TEMPLATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["version", "providers"],
    "properties": {
        "version": {"type": "string", "minLength": 1},
        "providers": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "provider_id",
                    "operator_family",
                    "api_key_env",
                    "operator_evidence_url",
                    "chains",
                ],
                "properties": {
                    "provider_id": {"type": "string", "minLength": 1},
                    "operator_family": {"type": "string", "minLength": 1},
                    "api_key_env": {"type": "string", "pattern": "^CHRONOS_[A-Z0-9_]+_API_KEY$"},
                    "operator_evidence_url": {"type": "string", "pattern": "^https://"},
                    "chains": {
                        "type": "object",
                        "minProperties": 1,
                        "additionalProperties": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["chain_id", "endpoint_template"],
                            "properties": {
                                "chain_id": {"type": "string", "pattern": "^0x[0-9a-f]+$"},
                                "endpoint_template": {"type": "string", "pattern": "^https://"},
                            },
                        },
                    },
                },
            },
        },
    },
}


class ManagedProviderConfigurationError(ValueError):
    """Fail-closed, machine-readable managed-provider configuration blocker."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        chain: str | None = None,
        operator_family: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.chain = chain
        self.operator_family = operator_family


@dataclass(frozen=True)
class ManagedProviderCredentialSource:
    operator_family: str
    chain: str
    url_env: str


_DEFAULT_CREDENTIAL_SOURCES: tuple[ManagedProviderCredentialSource, ...] = (
    ManagedProviderCredentialSource(
        operator_family="alchemy",
        chain="arbitrum",
        url_env="CHRONOS_ALCHEMY_ARBITRUM_URL",
    ),
    ManagedProviderCredentialSource(
        operator_family="infura",
        chain="arbitrum",
        url_env="CHRONOS_INFURA_ARBITRUM_URL",
    ),
)


def _template_sha256(template: str) -> str:
    return hashlib.sha256(template.encode("utf-8")).hexdigest()


def _validate_endpoint_template(template: str, *, provider_id: str, chain: str) -> None:
    if template.count("{api_key}") != 1:
        raise ManagedProviderConfigurationError(
            "invalid_endpoint_template",
            f"{provider_id}/{chain} endpoint_template must contain exactly one api_key placeholder",
            chain=chain,
        )
    without_key = template.replace("{api_key}", "")
    if "{" in without_key or "}" in without_key:
        raise ManagedProviderConfigurationError(
            "invalid_endpoint_template",
            f"{provider_id}/{chain} endpoint_template contains an unsupported placeholder",
            chain=chain,
        )
    parsed = urlsplit(template)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ManagedProviderConfigurationError(
            "invalid_endpoint_template",
            f"{provider_id}/{chain} endpoint_template must be a credential-free HTTPS URL template",
            chain=chain,
        )


@dataclass(frozen=True)
class ManagedProviderTemplate:
    provider_id: str
    operator_family: str
    api_key_env: str
    operator_evidence_url: str
    chain: str
    chain_id: str
    endpoint_template: str
    endpoint_template_sha256: str

    @classmethod
    def from_mapping(
        cls,
        provider: Mapping[str, Any],
        chain: str,
        chain_config: Mapping[str, Any],
    ) -> "ManagedProviderTemplate":
        normalized_chain = chain.strip().lower()
        if normalized_chain not in SUPPORTED_CHAINS:
            raise ManagedProviderConfigurationError(
                "unsupported_chain",
                f"managed provider template declares unsupported chain: {chain}",
                chain=normalized_chain,
            )
        provider_id = str(provider["provider_id"]).strip().lower()
        family = str(provider["operator_family"]).strip().lower()
        endpoint_template = str(chain_config["endpoint_template"]).strip()
        _validate_endpoint_template(endpoint_template, provider_id=provider_id, chain=normalized_chain)
        return cls(
            provider_id=f"{provider_id}-{normalized_chain}",
            operator_family=family,
            api_key_env=str(provider["api_key_env"]).strip(),
            operator_evidence_url=str(provider["operator_evidence_url"]).strip(),
            chain=normalized_chain,
            chain_id=str(chain_config["chain_id"]).strip().lower(),
            endpoint_template=endpoint_template,
            endpoint_template_sha256=_template_sha256(endpoint_template),
        )

    @property
    def identity_evidence(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "operator_family": self.operator_family,
            "chain": self.chain,
            "expected_chain_id": self.chain_id,
            "operator_evidence_url": self.operator_evidence_url,
            "public_endpoint_template": self.endpoint_template,
            "endpoint_template_sha256": self.endpoint_template_sha256,
        }


@dataclass(frozen=True)
class ManagedProviderTemplateRegistry:
    version: str
    templates: tuple[ManagedProviderTemplate, ...]

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "ManagedProviderTemplateRegistry":
        try:
            jsonschema.validate(instance=dict(mapping), schema=_TEMPLATE_SCHEMA)
        except jsonschema.ValidationError as exc:
            raise ManagedProviderConfigurationError(
                "invalid_template_schema",
                f"managed provider template schema validation failed at {list(exc.absolute_path)}: {exc.message}",
            ) from exc

        templates: list[ManagedProviderTemplate] = []
        seen_provider_ids: set[str] = set()
        seen_chain_families: set[tuple[str, str]] = set()
        for provider in mapping["providers"]:
            base_id = str(provider["provider_id"]).strip().lower()
            if base_id in seen_provider_ids:
                raise ManagedProviderConfigurationError(
                    "duplicate_provider_id",
                    f"duplicate managed provider_id: {base_id}",
                )
            seen_provider_ids.add(base_id)
            for chain, chain_config in provider["chains"].items():
                template = ManagedProviderTemplate.from_mapping(provider, chain, chain_config)
                family_key = (template.chain, template.operator_family)
                if family_key in seen_chain_families:
                    raise ManagedProviderConfigurationError(
                        "duplicate_operator_family",
                        f"duplicate operator family {template.operator_family} for {template.chain}",
                        chain=template.chain,
                        operator_family=template.operator_family,
                    )
                seen_chain_families.add(family_key)
                templates.append(template)

        return cls(version=str(mapping["version"]), templates=tuple(templates))

    def templates_for_chain(self, chain: str) -> list[ManagedProviderTemplate]:
        normalized = chain.strip().lower()
        if normalized not in SUPPORTED_CHAINS:
            raise ManagedProviderConfigurationError(
                "unsupported_chain",
                f"unsupported chain: {chain}",
                chain=normalized,
            )
        selected = sorted(
            (template for template in self.templates if template.chain == normalized),
            key=lambda template: template.operator_family,
        )
        if not selected:
            raise ManagedProviderConfigurationError(
                "unsupported_provider_chain_combination",
                f"no managed archive provider templates are configured for {normalized}",
                chain=normalized,
            )
        return selected

    def template_for_family_and_chain(
        self,
        operator_family: str,
        chain: str,
    ) -> ManagedProviderTemplate:
        normalized_chain = chain.strip().lower()
        normalized_family = operator_family.strip().lower()
        if normalized_chain not in SUPPORTED_CHAINS:
            raise ManagedProviderConfigurationError(
                "unsupported_chain",
                f"unsupported chain: {chain}",
                chain=normalized_chain,
                operator_family=normalized_family,
            )
        for template in self.templates:
            if template.chain == normalized_chain and template.operator_family == normalized_family:
                return template
        raise ManagedProviderConfigurationError(
            "unsupported_provider_chain_combination",
            f"no managed archive provider templates are configured for {normalized_family}/{normalized_chain}",
            chain=normalized_chain,
            operator_family=normalized_family,
        )


def _default_template_path() -> Path:
    return Path(__file__).resolve().parents[3] / "config" / "managed_archive_provider_templates.yaml"


def load_managed_provider_templates(
    path: str | Path | None = None,
) -> ManagedProviderTemplateRegistry:
    target = Path(path) if path is not None else _default_template_path()
    mapping = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(mapping, dict):
        raise ManagedProviderConfigurationError(
            "invalid_template_schema",
            "managed provider template file must contain a mapping",
        )
    return ManagedProviderTemplateRegistry.from_mapping(mapping)


def _normalized_credential_sources(
    credential_sources: Iterable[ManagedProviderCredentialSource] | None,
) -> dict[str, ManagedProviderCredentialSource]:
    configured = _DEFAULT_CREDENTIAL_SOURCES if credential_sources is None else tuple(credential_sources)
    by_family: dict[str, ManagedProviderCredentialSource] = {}
    for source in configured:
        family = source.operator_family.strip().lower()
        chain = source.chain.strip().lower()
        url_env = source.url_env.strip()
        if chain not in SUPPORTED_CHAINS:
            raise ManagedProviderConfigurationError(
                "unsupported_chain",
                f"unsupported chain: {source.chain}",
                chain=chain,
                operator_family=family or None,
            )
        if family in by_family:
            raise ManagedProviderConfigurationError(
                "duplicate_credential_source_family",
                f"duplicate managed credential source family: {family}",
                chain=chain,
                operator_family=family,
            )
        by_family[family] = ManagedProviderCredentialSource(
            operator_family=family,
            chain=chain,
            url_env=url_env,
        )
    return by_family


def _extract_api_key_from_authorized_source_url(
    *,
    source_template: ManagedProviderTemplate,
    source_url: str,
    source_env: str,
) -> str:
    parsed = urlsplit(source_url)
    template_parts = urlsplit(source_template.endpoint_template)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.hostname != template_parts.hostname
        or parsed.port != template_parts.port
    ):
        raise ManagedProviderConfigurationError(
            "invalid_api_key_source_url",
            f"authorized managed credential source {source_env} does not match the frozen {source_template.operator_family}/{source_template.chain} HTTPS endpoint shape",
            chain=source_template.chain,
            operator_family=source_template.operator_family,
        )

    prefix, suffix = template_parts.path.split("{api_key}", 1)
    if not parsed.path.startswith(prefix) or not parsed.path.endswith(suffix):
        raise ManagedProviderConfigurationError(
            "invalid_api_key_source_url",
            f"authorized managed credential source {source_env} does not match the frozen {source_template.operator_family}/{source_template.chain} HTTPS endpoint shape",
            chain=source_template.chain,
            operator_family=source_template.operator_family,
        )

    end_index = len(parsed.path) - len(suffix) if suffix else len(parsed.path)
    encoded_api_key = parsed.path[len(prefix) : end_index]
    if not encoded_api_key:
        raise ManagedProviderConfigurationError(
            "invalid_api_key_source_url",
            f"authorized managed credential source {source_env} is missing a non-empty credential",
            chain=source_template.chain,
            operator_family=source_template.operator_family,
        )
    api_key = unquote(encoded_api_key)
    if not api_key:
        raise ManagedProviderConfigurationError(
            "invalid_api_key_source_url",
            f"authorized managed credential source {source_env} is missing a non-empty credential",
            chain=source_template.chain,
            operator_family=source_template.operator_family,
        )
    if quote(api_key, safe="") != encoded_api_key:
        raise ManagedProviderConfigurationError(
            "invalid_api_key_source_url",
            f"authorized managed credential source {source_env} does not preserve the frozen credential placeholder shape",
            chain=source_template.chain,
            operator_family=source_template.operator_family,
        )
    return api_key


def _resolve_managed_api_key(
    template: ManagedProviderTemplate,
    *,
    templates: ManagedProviderTemplateRegistry,
    env: Mapping[str, str],
    credential_sources: dict[str, ManagedProviderCredentialSource],
) -> str:
    direct_api_key = str(env.get(template.api_key_env, "")).strip()
    if direct_api_key:
        return direct_api_key

    source = credential_sources.get(template.operator_family)
    if source is None:
        raise ManagedProviderConfigurationError(
            "missing_api_key",
            f"required managed provider environment variable is missing: {template.api_key_env}",
            chain=template.chain,
            operator_family=template.operator_family,
        )

    source_url = str(env.get(source.url_env, "")).strip()
    if not source_url:
        raise ManagedProviderConfigurationError(
            "missing_api_key",
            f"required managed provider environment variable is missing: {template.api_key_env} or authorized credential source {source.url_env}",
            chain=template.chain,
            operator_family=template.operator_family,
        )

    source_template = templates.template_for_family_and_chain(source.operator_family, source.chain)
    return _extract_api_key_from_authorized_source_url(
        source_template=source_template,
        source_url=source_url,
        source_env=source.url_env,
    )


def providers_for_chain_from_managed_env(
    chain: str,
    *,
    templates: ManagedProviderTemplateRegistry,
    env: Mapping[str, str] | None = None,
    artifact_root: str | Path | None = None,
    timeout: int = 30,
    retries: int = 3,
    backoff_seconds: float = 0.25,
    credential_sources: Iterable[ManagedProviderCredentialSource] | None = None,
) -> list[Any]:
    # Lazy import avoids a module cycle: onchain owns the transport class and
    # delegates only managed configuration expansion to this module.
    from chronosaudit_stage2.onchain import JsonRpcProvider

    environ = os.environ if env is None else env
    selected = templates.templates_for_chain(chain)
    source_map = _normalized_credential_sources(credential_sources)
    if len({template.operator_family for template in selected}) < 2:
        raise ManagedProviderConfigurationError(
            "insufficient_independent_provider_families",
            f"{chain} requires at least two distinct managed operator families",
            chain=chain,
        )

    providers: list[JsonRpcProvider] = []
    for template in selected:
        api_key = _resolve_managed_api_key(
            template,
            templates=templates,
            env=environ,
            credential_sources=source_map,
        )
        endpoint = template.endpoint_template.format(api_key=quote(api_key, safe=""))
        providers.append(
            JsonRpcProvider(
                provider_id=template.provider_id,
                url=endpoint,
                timeout=timeout,
                max_retries=retries,
                backoff_seconds=backoff_seconds,
                provider_family=template.operator_family,
                artifact_root=artifact_root,
                provider_identity_evidence=template.identity_evidence,
            )
        )

    if len({provider.provider_family for provider in providers}) < 2:
        raise ManagedProviderConfigurationError(
            "insufficient_independent_provider_families",
            f"{chain} managed provider resolution did not produce two independent operator families",
            chain=chain,
        )
    return providers


def managed_environment_present(
    templates: ManagedProviderTemplateRegistry,
    env: Mapping[str, str] | None = None,
    credential_sources: Iterable[ManagedProviderCredentialSource] | None = None,
) -> bool:
    environ = os.environ if env is None else env
    if any(str(environ.get(template.api_key_env, "")).strip() for template in templates.templates):
        return True
    return any(
        str(environ.get(source.url_env, "")).strip()
        for source in _normalized_credential_sources(credential_sources).values()
    )


def preflight_managed_provider(
    provider: Any,
    *,
    historical_block_number: int,
    representative_address: str,
) -> dict[str, Any]:
    """Prove chain identity and historical EIP-1898 read support.

    The caller chooses a representative old block/address from its frozen plan.
    Qualification is fail-closed and requires persisted, hash-bound response
    evidence for every check. This function is inert until explicitly called by
    the authorized live preflight workflow.
    """

    from chronosaudit_stage2.onchain import (
        EIP1967_IMPLEMENTATION_SLOT,
        block_tag,
        canonical_block_selector,
        normalize_block_header,
        normalize_hex,
    )

    if historical_block_number < 0:
        raise ValueError("historical_block_number must be non-negative")
    address = normalize_hex(representative_address)
    if len(address) != 42:
        raise ValueError("representative_address must be 20 bytes")

    identity = dict(getattr(provider, "provider_identity_evidence", {}) or {})
    expected_chain_id = str(identity.get("expected_chain_id", "")).strip().lower()
    checks = {
        "chain_id": "not_run",
        "historical_block": "not_run",
        "eip1898_code": "not_run",
        "eip1898_storage": "not_run",
    }
    blockers: list[str] = []
    observations: list[dict[str, Any]] = []

    def observe(method: str, params: list[Any]) -> Any:
        observation = provider.call(method, params)
        observations.append(dict(observation.__dict__))
        return observation

    def evidence_complete(observation: Any) -> bool:
        return bool(
            observation.error is None
            and observation.request_sha256
            and observation.response_sha256
            and observation.raw_response_path
            and observation.observed_at_utc
        )

    chain_observation = observe("eth_chainId", [])
    if not evidence_complete(chain_observation):
        blockers.append("chain_id_evidence_incomplete")
    else:
        try:
            actual_chain_id = int(str(chain_observation.result), 16)
            expected_chain_id_value = int(expected_chain_id, 16)
        except (TypeError, ValueError):
            actual_chain_id = -1
            expected_chain_id_value = -2
        if actual_chain_id != expected_chain_id_value:
            blockers.append("chain_id_mismatch")
        else:
            checks["chain_id"] = "pass"

    block_observation = observe("eth_getBlockByNumber", [block_tag(historical_block_number), False])
    block_header = None
    if not evidence_complete(block_observation):
        blockers.append("historical_block_failed")
    else:
        try:
            block_header = normalize_block_header(block_observation.result)
        except (TypeError, ValueError):
            block_header = None
        if not block_header or int(block_header["number"], 16) != historical_block_number:
            blockers.append("historical_block_mismatch")
        else:
            checks["historical_block"] = "pass"

    selector = canonical_block_selector(block_header["hash"]) if block_header else None
    if selector is not None:
        code_observation = observe("eth_getCode", [address, selector])
        if not evidence_complete(code_observation):
            blockers.append("eip1898_code_failed")
        else:
            try:
                normalize_hex(code_observation.result)
                checks["eip1898_code"] = "pass"
            except (TypeError, ValueError):
                blockers.append("eip1898_code_malformed")

        storage_observation = observe(
            "eth_getStorageAt",
            [address, EIP1967_IMPLEMENTATION_SLOT, selector],
        )
        if not evidence_complete(storage_observation):
            blockers.append("eip1898_storage_failed")
        else:
            try:
                storage_word = normalize_hex(storage_observation.result)
                if len(storage_word) != 66:
                    raise ValueError("storage word must be 32 bytes")
                checks["eip1898_storage"] = "pass"
            except (TypeError, ValueError):
                blockers.append("eip1898_storage_malformed")

    return {
        "status": "eligible" if not blockers and all(value == "pass" for value in checks.values()) else "blocked",
        "provider_id": getattr(provider, "provider_id", ""),
        "operator_family": getattr(provider, "provider_family", "unverified"),
        "provider_identity_evidence": identity,
        "historical_block_number": historical_block_number,
        "representative_address": address,
        "block_selector": selector,
        "checks": checks,
        "blockers": blockers,
        "observations": observations,
    }


def redacted_managed_endpoint(endpoint: str) -> str:
    """Public helper for evidence writers; never expose a runtime API token."""

    return redact_endpoint(endpoint)
