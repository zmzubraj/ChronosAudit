from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from .providers import ProviderRecord, ProviderRegistry


class ControlProviderIdentityEvidenceError(ValueError):
    """Raised when provider documentation evidence is incomplete or unsafe."""


_CAPTURE_SCHEMA = "chronosaudit.control_provider_document_capture_index.v1"
_REVIEW_SCHEMA = "chronosaudit.control_provider_identity_evidence_review.v1"
_OFFICIAL_HOST_SUFFIXES = {
    "alchemy": ("alchemy.com",),
    "infura": ("infura.io",),
    "quicknode": ("quicknode.com",),
    "chainstack": ("chainstack.com",),
    "publicnode": ("publicnode.com",),
    "1rpc": ("docs.1rpc.io",),
    "base-official": ("docs.base.org",),
    "bnb-official": ("docs.bnbchain.org",),
    "arbitrum-official": ("docs.arbitrum.io",),
    "blockreq": ("docs.blockreq.com",),
    "drpc": ("drpc.org",),
    "nodereal": ("docs.nodereal.io",),
    "onfinality": ("onfinality.io",),
    "solidrpc": ("solidrpc.io",),
    "tenderly": ("tenderly.co",),
}
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordinary_file(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlProviderIdentityEvidenceError(f"{label}_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityEvidenceError(f"{label}_missing") from exc
    if not resolved.is_file():
        raise ControlProviderIdentityEvidenceError(f"{label}_not_ordinary_file")
    return resolved


def _ordinary_directory(path: Path, label: str) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ControlProviderIdentityEvidenceError(f"{label}_not_ordinary_directory")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityEvidenceError(f"{label}_missing") from exc
    if not resolved.is_dir():
        raise ControlProviderIdentityEvidenceError(f"{label}_not_ordinary_directory")
    return resolved


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlProviderIdentityEvidenceError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlProviderIdentityEvidenceError(f"{label}_root_invalid")
    return payload


def _is_sha256(value: object) -> bool:
    text = str(value or "").lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _official_https_url(value: object, operator_family: str, label: str) -> str:
    url = str(value or "").strip()
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username or parts.password:
        raise ControlProviderIdentityEvidenceError(f"{label}_invalid")
    suffixes = _OFFICIAL_HOST_SUFFIXES.get(operator_family)
    if not suffixes or not any(host == suffix or host.endswith(f".{suffix}") for suffix in suffixes):
        raise ControlProviderIdentityEvidenceError(f"{label}_not_official_host")
    return url


def _capture_file(evidence_root: Path, relative_value: object) -> tuple[Path, str]:
    relative_text = str(relative_value or "").strip()
    relative = Path(relative_text)
    if not relative_text or relative.is_absolute():
        raise ControlProviderIdentityEvidenceError("capture_path_outside_evidence_root")
    candidate = evidence_root / relative
    if candidate.is_symlink():
        raise ControlProviderIdentityEvidenceError("capture_not_ordinary_file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ControlProviderIdentityEvidenceError("capture_missing") from exc
    try:
        resolved.relative_to(evidence_root)
    except ValueError as exc:
        raise ControlProviderIdentityEvidenceError("capture_path_outside_evidence_root") from exc
    if not resolved.is_file():
        raise ControlProviderIdentityEvidenceError("capture_not_ordinary_file")
    return resolved, relative.as_posix()


def _tracking_providers(registry: ProviderRegistry) -> dict[str, ProviderRecord]:
    providers = {
        provider.provider_id: provider
        for provider in registry.providers
        if provider.tracking_enabled
    }
    if not providers:
        raise ControlProviderIdentityEvidenceError("tracking_provider_set_empty")
    return providers


def _documented_endpoint_variants(provider: ProviderRecord) -> set[str]:
    endpoint = provider.public_endpoint
    if provider.endpoint_env is not None:
        hostname = str(urlsplit(endpoint).hostname or "").lower()
        return {endpoint, hostname}
    if provider.api_key_env is None:
        return {endpoint}
    return {
        endpoint,
        endpoint.replace("{api_key}", "API_KEY"),
        endpoint.replace("{api_key}", "YOUR_ALCHEMY_API_KEY"),
        endpoint.replace("{api_key}", "<YOUR-API-KEY>"),
    }


def build_control_provider_identity_evidence_review(
    *,
    provider_registry_path: Path,
    capture_index_path: Path,
    evidence_root: Path,
) -> dict[str, object]:
    """Build a documentation-bound review packet without verifying or authorizing providers."""
    registry_path = _ordinary_file(provider_registry_path, "provider_registry")
    index_path = _ordinary_file(capture_index_path, "capture_index")
    root = _ordinary_directory(evidence_root, "evidence_root")
    try:
        registry = ProviderRegistry.from_path(registry_path)
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlProviderIdentityEvidenceError("provider_registry_invalid") from exc
    providers = _tracking_providers(registry)
    index = _load_json_object(index_path, "capture_index")
    if index.get("schema_version") != _CAPTURE_SCHEMA:
        raise ControlProviderIdentityEvidenceError("capture_index_schema_invalid")
    captures = index.get("captures")
    if not isinstance(captures, list) or not captures:
        raise ControlProviderIdentityEvidenceError("capture_index_captures_invalid")

    seen_sources: set[str] = set()
    provider_to_source: dict[str, str] = {}
    normalized_captures: list[dict[str, object]] = []
    for raw_capture in captures:
        if not isinstance(raw_capture, Mapping):
            raise ControlProviderIdentityEvidenceError("capture_invalid")
        source_id = str(raw_capture.get("source_id") or "").strip()
        family = str(raw_capture.get("operator_family") or "").strip().lower()
        if not source_id or source_id in seen_sources:
            raise ControlProviderIdentityEvidenceError("capture_source_id_invalid")
        seen_sources.add(source_id)
        if family not in _OFFICIAL_HOST_SUFFIXES:
            raise ControlProviderIdentityEvidenceError("capture_operator_family_invalid")
        source_url = _official_https_url(raw_capture.get("source_url"), family, "capture_source_url")
        final_url = _official_https_url(raw_capture.get("final_url"), family, "capture_final_url")
        captured_at = str(raw_capture.get("captured_at_utc") or "")
        if not _UTC_SECONDS.fullmatch(captured_at):
            raise ControlProviderIdentityEvidenceError("capture_time_invalid")
        if raw_capture.get("http_status") != 200:
            raise ControlProviderIdentityEvidenceError("capture_http_status_invalid")
        expected_sha = str(raw_capture.get("content_sha256") or "").lower()
        if not _is_sha256(expected_sha):
            raise ControlProviderIdentityEvidenceError("capture_content_sha256_invalid")
        capture_path, capture_relative_path = _capture_file(root, raw_capture.get("captured_path"))
        if _sha256_file(capture_path) != expected_sha:
            raise ControlProviderIdentityEvidenceError("capture_content_sha256_mismatch")
        try:
            content = capture_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ControlProviderIdentityEvidenceError("capture_text_invalid") from exc
        provider_ids = raw_capture.get("supported_provider_ids")
        if not isinstance(provider_ids, list) or not provider_ids:
            raise ControlProviderIdentityEvidenceError("capture_provider_ids_invalid")
        normalized_provider_ids: list[str] = []
        for raw_provider_id in provider_ids:
            provider_id = str(raw_provider_id or "").strip()
            provider = providers.get(provider_id)
            if provider is None:
                raise ControlProviderIdentityEvidenceError("capture_provider_id_unknown")
            if provider_id in provider_to_source:
                raise ControlProviderIdentityEvidenceError("capture_provider_id_duplicate")
            if provider.operator_family != family:
                raise ControlProviderIdentityEvidenceError("provider_operator_family_mismatch")
            if not any(
                variant in content for variant in _documented_endpoint_variants(provider)
            ):
                raise ControlProviderIdentityEvidenceError("provider_endpoint_not_in_capture")
            provider_to_source[provider_id] = source_id
            normalized_provider_ids.append(provider_id)
        normalized_captures.append(
            {
                "source_id": source_id,
                "source_url": source_url,
                "final_url": final_url,
                "captured_path": capture_relative_path,
                "captured_at_utc": captured_at,
                "http_status": 200,
                "content_sha256": expected_sha,
                "operator_family": family,
                "supported_provider_ids": sorted(normalized_provider_ids),
            }
        )

    missing = sorted(set(providers) - set(provider_to_source))
    if missing:
        raise ControlProviderIdentityEvidenceError(
            f"tracking_provider_evidence_incomplete:{','.join(missing)}"
        )
    provider_rows = [
        {
            "provider_id": provider.provider_id,
            "chain": provider.chain,
            "operator_family": provider.operator_family,
            "public_endpoint": provider.public_endpoint,
            "public_endpoint_id": provider.public_endpoint_id,
            "api_key_env": provider.api_key_env,
            "endpoint_env": provider.endpoint_env,
            "source_id": provider_to_source[provider.provider_id],
            "registry_operator_verified": provider.operator_verified,
            "review_operator_verified": False,
        }
        for provider in sorted(providers.values(), key=lambda item: item.provider_id)
    ]
    review: dict[str, object] = {
        "schema_version": _REVIEW_SCHEMA,
        "decision": "EVIDENCE_CAPTURED_AWAITING_ACCOUNTABLE_PROVIDER_IDENTITY_REVIEW",
        "provider_registry_sha256": _sha256_file(registry_path),
        "capture_index_sha256": _sha256_file(index_path),
        "provider_count": len(provider_rows),
        "provider_ids": [row["provider_id"] for row in provider_rows],
        "providers": provider_rows,
        "captures": sorted(normalized_captures, key=lambda item: str(item["source_id"])),
        "provider_identity_verified": False,
        "operator_verified": False,
        "reviewer_signature_required": True,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
    review["review_payload_sha256"] = _canonical_sha256(review)
    return review


def verify_control_provider_identity_evidence_review(
    *,
    review_path: Path,
    provider_registry_path: Path,
    capture_index_path: Path,
    evidence_root: Path,
) -> dict[str, object]:
    """Rebuild and compare a persisted non-authorizing review packet."""
    persisted_path = _ordinary_file(review_path, "review")
    persisted = _load_json_object(persisted_path, "review")
    expected = build_control_provider_identity_evidence_review(
        provider_registry_path=provider_registry_path,
        capture_index_path=capture_index_path,
        evidence_root=evidence_root,
    )
    if persisted != expected:
        raise ControlProviderIdentityEvidenceError("review_content_mismatch")
    return {
        "schema_version": "chronosaudit.control_provider_identity_evidence_verification.v1",
        "decision": "PROVIDER_IDENTITY_EVIDENCE_REVIEW_VERIFIED_NON_AUTHORIZING",
        "review_sha256": _sha256_file(persisted_path),
        "review_payload_sha256": expected["review_payload_sha256"],
        "provider_count": expected["provider_count"],
        "provider_identity_verified": False,
        "rpc_authorized": False,
        "selection_authorized": False,
        "stage_promotion_authorized": False,
        "recovery3_mutation_authorized": False,
    }
