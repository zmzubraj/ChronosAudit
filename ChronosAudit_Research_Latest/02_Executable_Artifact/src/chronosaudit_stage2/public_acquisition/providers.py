from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

import yaml

from .model import SUPPORTED_CHAINS

_SECRET_QUERY_KEYS = {
    "apikey",
    "api_key",
    "key",
    "token",
    "secret",
    "signature",
    "sig",
    "access_token",
    "auth",
    "authorization",
    "password",
}

# NodeReal publishes this exact starter key as public and shareable in its
# official API overview. Keeping this one documented value visible lets the
# hash-bound provider projection remain callable without weakening default
# redaction for any other credential-like path segment.
_DOCUMENTED_PUBLIC_PATH_SEGMENTS = {
    "64a9df0874fb4a93b9d0a3849de012d3",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _normalize_chain(chain: str) -> str:
    normalized = chain.strip().lower()
    if normalized not in SUPPORTED_CHAINS:
        raise ValueError(f"unsupported chain: {chain}")
    return normalized


def _segment_is_secret(segment: str) -> bool:
    if not segment:
        return False
    lowered = segment.lower()
    if lowered in _DOCUMENTED_PUBLIC_PATH_SEGMENTS:
        return False
    if re.fullmatch(r"v\d+", lowered):
        return False
    if lowered in {"rpc", "jsonrpc", "api", "eth", "bsc", "base", "arb", "arbitrum"}:
        return False
    return len(segment) >= 6 and not segment.isdigit() and (
        any(char.isupper() for char in segment)
        or bool(re.search(r"[a-zA-Z]", segment) and re.search(r"\d", segment))
    )


def redact_endpoint(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    path_segments = parts.path.split("/")
    redacted_path = "/".join("<redacted>" if _segment_is_secret(segment) else segment for segment in path_segments)

    query_parts: list[str] = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        safe_value = "<redacted>" if key.lower() in _SECRET_QUERY_KEYS else value
        query_parts.append(f"{quote(key, safe='')}={quote(safe_value, safe='<>')}")

    return urlunsplit((parts.scheme, parts.netloc, redacted_path, "&".join(query_parts), parts.fragment))


def endpoint_id(endpoint: str) -> str:
    return hashlib.sha256(redact_endpoint(endpoint).encode("utf-8")).hexdigest()


def _validate_optional_sha256(name: str, value: str | None) -> None:
    if value is None:
        return
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower()):
        raise ValueError(f"{name} must be a sha256 hex digest when provided")


@dataclass(frozen=True)
class ProviderRecord:
    provider_id: str
    chain: str
    endpoint: str
    operator_family: str
    discovery_source: str
    tracking_enabled: bool
    operator_evidence_url: str | None
    operator_evidence_sha256: str | None
    operator_verified: bool
    api_key_env: str | None = None
    endpoint_env: str | None = None

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "ProviderRecord":
        provider_id = str(mapping["provider_id"]).strip()
        if not provider_id:
            raise ValueError("provider_id must be non-empty")
        endpoint = str(mapping["endpoint"]).strip()
        if not endpoint:
            raise ValueError("endpoint must be non-empty")
        operator_family = str(mapping["operator_family"]).strip().lower()
        if not operator_family:
            raise ValueError("operator_family must be non-empty")
        api_key_env_value = mapping.get("api_key_env")
        api_key_env = (
            str(api_key_env_value).strip() if api_key_env_value is not None else None
        )
        endpoint_env_value = mapping.get("endpoint_env")
        endpoint_env = (
            str(endpoint_env_value).strip()
            if endpoint_env_value is not None
            else None
        )
        if api_key_env is not None and endpoint_env is not None:
            raise ValueError("api_key_env and endpoint_env are mutually exclusive")
        placeholder_count = endpoint.count("{api_key}")
        if placeholder_count:
            if placeholder_count != 1 or any(
                marker in endpoint.replace("{api_key}", "")
                for marker in ("{", "}")
            ):
                raise ValueError(
                    "managed endpoint must contain exactly one api_key placeholder"
                )
            if not api_key_env or not re.fullmatch(
                r"CHRONOS_[A-Z0-9_]+_API_KEY", api_key_env
            ):
                raise ValueError(
                    "managed endpoint requires a CHRONOS_*_API_KEY environment variable"
                )
            parsed = urlsplit(endpoint)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "managed endpoint must be a credential-free HTTPS URL template"
                )
        elif api_key_env is not None:
            raise ValueError("api_key_env is allowed only for a managed endpoint template")
        if endpoint_env is not None:
            if not re.fullmatch(r"CHRONOS_[A-Z0-9_]+_URL", endpoint_env):
                raise ValueError(
                    "full endpoint binding requires a CHRONOS_*_URL environment variable"
                )
            parsed = urlsplit(endpoint)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "full endpoint binding requires a credential-free HTTPS host boundary"
                )
        _validate_optional_sha256("operator_evidence_sha256", mapping.get("operator_evidence_sha256"))
        return cls(
            provider_id=provider_id,
            chain=_normalize_chain(str(mapping["chain"])),
            endpoint=endpoint,
            operator_family=operator_family,
            discovery_source=str(mapping.get("discovery_source", "")).strip(),
            tracking_enabled=bool(mapping.get("tracking_enabled", True)),
            operator_evidence_url=mapping.get("operator_evidence_url"),
            operator_evidence_sha256=mapping.get("operator_evidence_sha256"),
            operator_verified=bool(mapping.get("operator_verified", False)),
            api_key_env=api_key_env,
            endpoint_env=endpoint_env,
        )

    def resolved_endpoint(self, env: Mapping[str, str] | None = None) -> str:
        """Resolve a managed template at runtime without persisting its secret."""
        if self.api_key_env is None and self.endpoint_env is None:
            return self.endpoint
        environ = os.environ if env is None else env
        if self.endpoint_env is not None:
            runtime_endpoint = str(environ.get(self.endpoint_env, "")).strip()
            if not runtime_endpoint:
                raise ValueError(
                    "required managed provider environment variable is missing: "
                    f"{self.endpoint_env}"
                )
            public = urlsplit(self.endpoint)
            runtime = urlsplit(runtime_endpoint)
            expected_host = str(public.hostname or "").lower()
            runtime_host = str(runtime.hostname or "").lower()
            if (
                runtime.scheme != "https"
                or not runtime_host
                or runtime.username
                or runtime.password
                or runtime.fragment
                or (
                    runtime_host != expected_host
                    and not runtime_host.endswith(f".{expected_host}")
                )
            ):
                raise ValueError(
                    "managed provider URL is outside its configured HTTPS host boundary: "
                    f"{self.endpoint_env}"
                )
            return runtime_endpoint
        assert self.api_key_env is not None
        api_key = str(environ.get(self.api_key_env, "")).strip()
        if not api_key:
            raise ValueError(
                f"required managed provider environment variable is missing: {self.api_key_env}"
            )
        return self.endpoint.format(api_key=quote(api_key, safe=""))

    @property
    def public_endpoint(self) -> str:
        return redact_endpoint(self.endpoint)

    @property
    def public_endpoint_id(self) -> str:
        return endpoint_id(self.endpoint)


@dataclass(frozen=True)
class ProviderRegistry:
    providers: tuple[ProviderRecord, ...]

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "ProviderRegistry":
        providers = tuple(ProviderRecord.from_mapping(item) for item in mapping.get("providers", []))
        seen_ids: set[str] = set()
        for provider in providers:
            if provider.provider_id in seen_ids:
                raise ValueError(f"duplicate provider_id: {provider.provider_id}")
            seen_ids.add(provider.provider_id)
        return cls(providers=providers)

    @classmethod
    def from_path(cls, path: str | Path | None = None) -> "ProviderRegistry":
        target = Path(path) if path is not None else _project_root() / "config" / "public_provider_registry.yaml"
        return cls.from_mapping(yaml.safe_load(target.read_text(encoding="utf-8")))

    def providers_for_chain(self, chain: str, verified_only: bool = False) -> list[ProviderRecord]:
        normalized = _normalize_chain(chain)
        return [
            provider
            for provider in self.providers
            if provider.chain == normalized and (provider.operator_verified or not verified_only)
        ]

    def independent_family_count(self, chain: str, verified_only: bool = True) -> int:
        return len({provider.operator_family for provider in self.providers_for_chain(chain, verified_only=verified_only)})
