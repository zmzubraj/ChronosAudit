from __future__ import annotations

import hashlib
import json
import os
import random
import re
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from chronosaudit_stage2.public_acquisition.managed_providers import ManagedProviderConfigurationError
from chronosaudit_stage2.public_acquisition.providers import endpoint_id, redact_endpoint

EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
BEACON_IMPLEMENTATION_SELECTOR = "0x5c60da1b"  # implementation()


@dataclass(frozen=True)
class ProviderObservation:
    provider_id: str
    method: str
    params: list[Any]
    result: Any
    observed_at_unix: int
    error: str | None = None
    response_sha256: str | None = None
    provider_family: str = "unverified"
    request_sha256: str | None = None
    raw_response_path: str | None = None
    http_status: int | None = None
    attempt: int = 1
    observed_at_utc: str | None = None


class JsonRpcProvider:
    def __init__(
        self,
        provider_id: str,
        url: str,
        timeout: int = 30,
        max_retries: int = 3,
        backoff_seconds: float = 0.25,
        provider_family: str | None = None,
        artifact_root: str | Path | None = None,
        provider_identity_evidence: dict[str, Any] | None = None,
    ):
        self.provider_id = provider_id
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.provider_family = provider_family or "unverified"
        self.artifact_root = Path(artifact_root) if artifact_root is not None else None
        self.provider_identity_evidence = dict(provider_identity_evidence or {})

    @property
    def public_endpoint(self) -> str:
        template = str(self.provider_identity_evidence.get("public_endpoint_template", "")).strip()
        if template:
            return template
        return redact_endpoint(self.url)

    @property
    def public_endpoint_id(self) -> str:
        template_hash = str(self.provider_identity_evidence.get("endpoint_template_sha256", "")).strip()
        return template_hash or endpoint_id(self.url)

    def _public_error(self, exc: BaseException | None) -> str:
        detail = str(exc).replace(self.url, self.public_endpoint)
        return f"{type(exc).__name__}: {detail}"

    def _persist_raw_response(self, raw: bytes) -> tuple[str, str | None]:
        response_hash = hashlib.sha256(raw).hexdigest()
        if self.artifact_root is None:
            return response_hash, None
        target = self.artifact_root / response_hash[:2] / f"{response_hash}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{response_hash}.",
            suffix=".tmp",
            dir=target.parent,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(file_descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, target)
        finally:
            temporary_path.unlink(missing_ok=True)
        return response_hash, str(target)

    def _sleep_before_retry(self, attempt: int) -> None:
        delay = self.backoff_seconds * (2 ** attempt)
        time.sleep(delay + random.uniform(0.0, delay / 4 if delay else 0.0))

    def call(self, method: str, params: list[Any]) -> ProviderObservation:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, separators=(",", ":")).encode()
        request_sha256 = hashlib.sha256(body).hexdigest()
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "ChronosAudit-Stage2/0.5"},
            method="POST",
        )
        now = int(time.time())
        observed_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        last_exc = None
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                    http_status = response.status
                payload = json.loads(raw.decode("utf-8"))
                response_hash, raw_path = self._persist_raw_response(raw)
                if "error" in payload:
                    err = json.dumps(payload["error"], sort_keys=True)
                    if attempt < self.max_retries and any(
                        x in err.lower()
                        for x in ("rate", "limit", "timeout", "temporar", "internal error", "precondition failure")
                    ):
                        self._sleep_before_retry(attempt)
                        continue
                    return ProviderObservation(
                        self.provider_id,
                        method,
                        params,
                        None,
                        now,
                        err,
                        response_hash,
                        provider_family=self.provider_family,
                        request_sha256=request_sha256,
                        raw_response_path=raw_path,
                        http_status=http_status,
                        attempt=attempt + 1,
                        observed_at_utc=observed_at_utc,
                    )
                return ProviderObservation(
                    self.provider_id,
                    method,
                    params,
                    payload.get("result"),
                    now,
                    None,
                    response_hash,
                    provider_family=self.provider_family,
                    request_sha256=request_sha256,
                    raw_response_path=raw_path,
                    http_status=http_status,
                    attempt=attempt + 1,
                    observed_at_utc=observed_at_utc,
                )
            except urllib.error.HTTPError as exc:
                last_exc = exc
                if exc.code in {408, 429, 500, 502, 503, 504} and attempt < self.max_retries:
                    self._sleep_before_retry(attempt)
                    continue
                break
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    self._sleep_before_retry(attempt)
                    continue
                break
        return ProviderObservation(
            self.provider_id,
            method,
            params,
            None,
            now,
            self._public_error(last_exc),
            None,
            provider_family=self.provider_family,
            request_sha256=request_sha256,
            raw_response_path=None,
            http_status=getattr(last_exc, "code", None),
            attempt=self.max_retries + 1,
            observed_at_utc=observed_at_utc,
        )


def block_tag(block_number: int) -> str:
    if block_number < 0:
        raise ValueError("block number must be non-negative")
    return hex(block_number)


def canonical_block_selector(block_hash: str) -> dict[str, Any]:
    value = normalize_hex(block_hash)
    if len(value) != 66:
        raise ValueError("block hash must be 32 bytes")
    return {"blockHash": value, "requireCanonical": True}


def normalize_hex(value: str | None) -> str:
    text = (value or "0x").lower()
    if not text.startswith("0x") or not re.fullmatch(r"0x[0-9a-f]*", text):
        raise ValueError(f"invalid hex value: {value}")
    if len(text) % 2 == 1:
        text = "0x0" + text[2:]
    return text


def normalize_block_header(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not value.get("hash") or not value.get("number"):
        raise ValueError("malformed block header")
    return {"hash": normalize_hex(value["hash"]), "number": normalize_hex(value["number"])}


def storage_word_to_address(word: str | None) -> str | None:
    value = normalize_hex(word)
    body = value[2:].rjust(64, "0")
    address = "0x" + body[-40:]
    return None if int(address, 16) == 0 else address


def call_word_to_address(word: str | None) -> str | None:
    if word is None:
        return None
    return storage_word_to_address(word)


def is_eip1167_minimal_proxy(code: str) -> str | None:
    body = normalize_hex(code)[2:]
    patterns = [
        r"^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$",
        r"^3d602d80600a3d3981f3363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$",
    ]
    for pattern in patterns:
        match = re.match(pattern, body)
        if match:
            return "0x" + match.group(1)
    return None


def strip_solidity_metadata(code: str) -> tuple[str, str]:
    """Return (normalized_code, status) using a conservative CBOR trailer check."""
    value = normalize_hex(code)
    raw = bytes.fromhex(value[2:])
    if len(raw) < 2:
        return value, "too_short"
    meta_len = int.from_bytes(raw[-2:], "big")
    if meta_len == 0 or meta_len + 2 > len(raw):
        return value, "metadata_not_recognized"
    start = len(raw) - meta_len - 2
    metadata = raw[start:-2]
    if not metadata or not 0xA0 <= metadata[0] <= 0xBF:
        return value, "metadata_length_inconsistent"
    return "0x" + raw[:start].hex(), "metadata_stripped"


def provider_consensus(
    providers: list[JsonRpcProvider],
    method: str,
    params: list[Any],
    normalizer: Callable[[Any], Any] = lambda x: x,
    minimum_agreement: int = 2,
    require_distinct_provider_families: bool = False,
) -> dict[str, Any]:
    observations = [provider.call(method, params) for provider in providers]
    counts: dict[str, int] = {}
    family_counts: dict[str, set[str]] = {}
    values: dict[str, Any] = {}
    normalized_errors: list[dict[str, str]] = []
    successful = 0
    for obs in observations:
        if obs.error is not None:
            continue
        try:
            normalized = normalizer(obs.result)
        except Exception as exc:  # normalization failure is evidence, not a crash
            normalized_errors.append({"provider_id": obs.provider_id, "error": f"{type(exc).__name__}: {exc}"})
            continue
        successful += 1
        key = json.dumps(normalized, sort_keys=True)
        counts[key] = counts.get(key, 0) + 1
        family_counts.setdefault(key, set())
        family = (obs.provider_family or "").strip().lower()
        if family and not family.startswith("unverified"):
            family_counts[key].add(family)
        values[key] = normalized
    if not counts:
        return {
            "status": "no_successful_provider",
            "value": None,
            "successful_count": successful,
            "normalization_errors": normalized_errors,
            "observations": [o.__dict__ for o in observations],
        }
    best_key = max(counts, key=lambda key: counts[key])
    best_count = counts[best_key]
    best_family_count = len(family_counts.get(best_key, set()))
    if require_distinct_provider_families:
        status = "consensus" if best_family_count >= minimum_agreement else "insufficient_independent_provider_families"
        agreement_count = best_family_count
    else:
        status = "consensus" if best_count >= minimum_agreement else "insufficient_agreement"
        agreement_count = best_count
    return {
        "status": status,
        "value": values[best_key] if status == "consensus" else None,
        "agreement_count": agreement_count,
        "agreement_provider_families": sorted(family_counts.get(best_key, set())),
        "successful_count": successful,
        "normalization_errors": normalized_errors,
        "observations": [o.__dict__ for o in observations],
    }


def provider_urls_from_env(
    chain: str,
    *,
    registry: Any | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 30,
    max_retries: int = 3,
    backoff_seconds: float = 0.25,
    artifact_root: str | Path | None = None,
) -> list[JsonRpcProvider]:
    environ = os.environ if env is None else env
    key = f"CHRONOS_{chain.upper()}_ARCHIVE_RPC_URLS"
    family_key = f"CHRONOS_{chain.upper()}_ARCHIVE_RPC_PROVIDER_FAMILIES"
    urls = [x.strip() for x in environ.get(key, "").split(",") if x.strip()]
    families = [x.strip().lower() for x in environ.get(family_key, "").split(",") if x.strip()]
    if urls and not families:
        raise ManagedProviderConfigurationError(
            "missing_explicit_provider_families",
            f"{family_key} is required whenever {key} is set",
            chain=chain,
        )
    if families and len(families) != len(urls):
        raise ManagedProviderConfigurationError(
            "explicit_provider_family_length_mismatch",
            f"{family_key} must match {key} length",
            chain=chain,
        )

    if not urls:
        from chronosaudit_stage2.public_acquisition.managed_providers import (
            load_managed_provider_templates,
            managed_environment_present,
            providers_for_chain_from_managed_env,
        )

        templates = load_managed_provider_templates()
        if not managed_environment_present(templates, environ):
            return []
        return providers_for_chain_from_managed_env(
            chain,
            templates=templates,
            env=environ,
            artifact_root=artifact_root,
            timeout=timeout,
            retries=max_retries,
            backoff_seconds=backoff_seconds,
        )

    verified_records = {}
    if registry is not None:
        for record in registry.providers_for_chain(chain, verified_only=True):
            verified_records[(endpoint_id(record.endpoint), record.operator_family, record.chain)] = record

    providers: list[JsonRpcProvider] = []
    for index, url in enumerate(urls, start=1):
        family = families[index - 1] if families else None
        exact_record = None
        if family is not None:
            exact_record = verified_records.get((endpoint_id(url), family, chain))
            if exact_record is None:
                raise ManagedProviderConfigurationError(
                    "explicit_provider_identity_unverified",
                    f"exact verified endpoint identity required for {family_key}",
                    chain=chain,
                    operator_family=family,
                )
        else:
            for candidate in verified_records.values():
                if candidate.chain == chain and endpoint_id(candidate.endpoint) == endpoint_id(url):
                    exact_record = candidate
                    break
        if family is None and exact_record is not None:
            family = exact_record.operator_family
        providers.append(
            JsonRpcProvider(
                provider_id=exact_record.provider_id if exact_record is not None else f"{chain}-provider-{index}",
                url=url,
                timeout=timeout,
                max_retries=max_retries,
                backoff_seconds=backoff_seconds,
                provider_family=family or "unverified",
                artifact_root=artifact_root,
            )
        )
    if len({provider.provider_family for provider in providers}) < 2:
        raise ManagedProviderConfigurationError(
            "insufficient_independent_provider_families",
            f"{chain} explicit provider resolution requires at least two distinct verified operator families",
            chain=chain,
        )
    return providers


def historical_identity_snapshot(
    address: str,
    block_number: int,
    providers: list[JsonRpcProvider],
    *,
    strict_provider_families: bool = False,
    agreed_block_hash: str | None = None,
) -> dict[str, Any]:
    """Reconstruct contract identity at a canonical historical block.

    The function intentionally fails closed unless at least two providers agree on
    the block hash and on all required historical reads. EIP-1898 block-hash
    selectors prevent a provider from silently serving a different same-height
    block. Beacon implementations are resolved with implementation() at the same
    canonical block. Diamond facets still require a dedicated loupe/event resolver
    and therefore remain an explicit downstream gate.
    """
    if len(providers) < 2:
        return {"status": "blocked_requires_two_archive_providers", "address": address, "block_number": block_number}

    if agreed_block_hash is None:
        tag = block_tag(block_number)
        block = provider_consensus(
            providers,
            "eth_getBlockByNumber",
            [tag, False],
            normalize_block_header,
            require_distinct_provider_families=strict_provider_families,
        )
        if block["status"] != "consensus" or not block["value"]:
            return {
                "status": "blocked_no_canonical_block_consensus",
                "address": address,
                "block_number": block_number,
                "block": block,
            }
        block_hash = block["value"]["hash"]
    else:
        block_hash = normalize_hex(agreed_block_hash)
        if len(block_hash) != 66:
            raise ValueError("agreed block hash must be 32 bytes")
        block = {
            "status": "caller_agreed_canonical_block",
            "value": {"number": block_tag(block_number), "hash": block_hash},
            "observations": [],
        }
    selector = canonical_block_selector(block_hash)

    code = provider_consensus(
        providers,
        "eth_getCode",
        [address, selector],
        normalize_hex,
        require_distinct_provider_families=strict_provider_families,
    )
    implementation = provider_consensus(
        providers,
        "eth_getStorageAt",
        [address, EIP1967_IMPLEMENTATION_SLOT, selector],
        storage_word_to_address,
        require_distinct_provider_families=strict_provider_families,
    )
    beacon = provider_consensus(
        providers,
        "eth_getStorageAt",
        [address, EIP1967_BEACON_SLOT, selector],
        storage_word_to_address,
        require_distinct_provider_families=strict_provider_families,
    )
    admin = provider_consensus(
        providers,
        "eth_getStorageAt",
        [address, EIP1967_ADMIN_SLOT, selector],
        storage_word_to_address,
        require_distinct_provider_families=strict_provider_families,
    )

    beacon_impl: dict[str, Any]
    if beacon["status"] == "consensus" and beacon.get("value"):
        beacon_impl = provider_consensus(
            providers,
            "eth_call",
            [{"to": beacon["value"], "data": BEACON_IMPLEMENTATION_SELECTOR}, selector],
            call_word_to_address,
            require_distinct_provider_families=strict_provider_families,
        )
    elif beacon["status"] == "consensus":
        beacon_impl = {"status": "not_applicable", "value": None, "observations": []}
    else:
        beacon_impl = {"status": "blocked_beacon_disputed", "value": None, "observations": []}

    minimal_proxy_target = None
    metadata_stripped_sha256 = None
    metadata_status = None
    runtime_sha256 = None
    if code["status"] == "consensus" and code.get("value") is not None:
        normalized_code = code["value"]
        minimal_proxy_target = is_eip1167_minimal_proxy(normalized_code)
        stripped, metadata_status = strip_solidity_metadata(normalized_code)
        runtime_sha256 = hashlib.sha256(bytes.fromhex(normalized_code[2:])).hexdigest()
        metadata_stripped_sha256 = hashlib.sha256(bytes.fromhex(stripped[2:])).hexdigest()

    required = [code, implementation, beacon, admin]
    if beacon.get("value"):
        required.append(beacon_impl)
    complete = all(x["status"] in {"consensus", "not_applicable"} for x in required)
    return {
        "status": "complete" if complete else "partial_or_disputed",
        "address": address.lower(),
        "block_number": block_number,
        "canonical_block_hash": block_hash,
        "block_consensus_reused": agreed_block_hash is not None,
        "eip1898_pinned": True,
        "block": block,
        "code": code,
        "runtime_bytecode_sha256": runtime_sha256,
        "metadata_stripped_bytecode_sha256": metadata_stripped_sha256,
        "metadata_status": metadata_status,
        "implementation": implementation,
        "beacon": beacon,
        "beacon_implementation": beacon_impl,
        "admin": admin,
        "eip1167_target": minimal_proxy_target,
        "diamond_resolution_status": "requires_loupe_or_historical_event_resolver",
    }
