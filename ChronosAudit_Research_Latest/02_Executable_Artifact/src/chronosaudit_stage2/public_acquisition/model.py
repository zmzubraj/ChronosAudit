from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

SUPPORTED_CHAINS = ("ethereum", "bsc", "base", "arbitrum")
ZERO_SHA256 = "0" * 64


class AcquisitionStatus(str, Enum):
    NOT_QUEUED = "NOT_QUEUED"
    QUEUED = "QUEUED"
    ATTEMPTED = "ATTEMPTED"
    PARTIAL = "PARTIAL"
    VERIFIED = "VERIFIED"
    DISPUTED = "DISPUTED"
    UNAVAILABLE = "UNAVAILABLE"
    POLICY_EXCLUDED = "POLICY_EXCLUDED"
    WAITING_EXTERNAL = "WAITING_EXTERNAL"
    STALE = "STALE"


_ALLOWED_TRANSITIONS: dict[AcquisitionStatus, set[AcquisitionStatus]] = {
    AcquisitionStatus.NOT_QUEUED: {AcquisitionStatus.QUEUED, AcquisitionStatus.POLICY_EXCLUDED},
    AcquisitionStatus.QUEUED: {
        AcquisitionStatus.ATTEMPTED,
        AcquisitionStatus.PARTIAL,
        AcquisitionStatus.DISPUTED,
        AcquisitionStatus.UNAVAILABLE,
        AcquisitionStatus.POLICY_EXCLUDED,
        AcquisitionStatus.WAITING_EXTERNAL,
        AcquisitionStatus.STALE,
    },
    AcquisitionStatus.ATTEMPTED: {
        AcquisitionStatus.PARTIAL,
        AcquisitionStatus.DISPUTED,
        AcquisitionStatus.UNAVAILABLE,
        AcquisitionStatus.WAITING_EXTERNAL,
        AcquisitionStatus.STALE,
    },
    AcquisitionStatus.PARTIAL: {
        AcquisitionStatus.DISPUTED,
        AcquisitionStatus.UNAVAILABLE,
        AcquisitionStatus.WAITING_EXTERNAL,
        AcquisitionStatus.STALE,
    },
    AcquisitionStatus.VERIFIED: {AcquisitionStatus.DISPUTED, AcquisitionStatus.STALE},
    AcquisitionStatus.DISPUTED: {
        AcquisitionStatus.WAITING_EXTERNAL,
        AcquisitionStatus.STALE,
    },
    AcquisitionStatus.UNAVAILABLE: {
        AcquisitionStatus.QUEUED,
        AcquisitionStatus.WAITING_EXTERNAL,
        AcquisitionStatus.STALE,
    },
    AcquisitionStatus.POLICY_EXCLUDED: {AcquisitionStatus.STALE},
    AcquisitionStatus.WAITING_EXTERNAL: {
        AcquisitionStatus.QUEUED,
        AcquisitionStatus.VERIFIED,
        AcquisitionStatus.DISPUTED,
        AcquisitionStatus.STALE,
    },
    AcquisitionStatus.STALE: {
        AcquisitionStatus.QUEUED,
        AcquisitionStatus.POLICY_EXCLUDED,
        AcquisitionStatus.WAITING_EXTERNAL,
    },
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_sha256(name: str, value: str | None) -> None:
    if value is None:
        return
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value.lower()):
        raise ValueError(f"{name} must be a 64-character sha256 hex digest")


def _validate_chain(chain: str) -> str:
    normalized = chain.strip().lower()
    if normalized not in SUPPORTED_CHAINS:
        raise ValueError(f"unsupported chain: {chain}")
    return normalized


def _validate_status(status: AcquisitionStatus | str) -> AcquisitionStatus:
    return status if isinstance(status, AcquisitionStatus) else AcquisitionStatus(status)


def validate_status_transition(
    previous_status: AcquisitionStatus | None,
    next_status: AcquisitionStatus | str,
) -> AcquisitionStatus:
    prior = previous_status or AcquisitionStatus.NOT_QUEUED
    target = _validate_status(next_status)
    allowed = _ALLOWED_TRANSITIONS[prior]
    if target not in allowed:
        raise ValueError(f"illegal acquisition status transition: {prior.value} -> {target.value}")
    return target


def _cell_id(case_id: str | None, chain: str, provider_id: str | None, method: str, block_selector: str | None) -> str:
    material = f"{case_id or ''}|{chain}|{provider_id or ''}|{method}|{block_selector or ''}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AcquisitionEvent:
    event_id: str
    cell_id: str
    case_id: str | None
    chain: str
    provider_id: str | None
    method: str
    block_selector: str | None
    status: AcquisitionStatus
    observed_at_utc: str
    request_sha256: str | None
    response_sha256: str | None
    raw_artifact_path: str | None
    error_class: str | None
    error_detail: str | None
    previous_event_sha256: str
    event_sha256: str

    @classmethod
    def create(
        cls,
        case_id: str | None,
        chain: str,
        provider_id: str | None,
        method: str,
        block_selector: str | None,
        status: AcquisitionStatus | str,
        *,
        observed_at_utc: str | None = None,
        request_sha256: str | None = None,
        response_sha256: str | None = None,
        raw_artifact_path: str | None = None,
        error_class: str | None = None,
        error_detail: str | None = None,
        previous_event_sha256: str = ZERO_SHA256,
        event_id: str | None = None,
    ) -> "AcquisitionEvent":
        chain_value = _validate_chain(chain)
        status_value = _validate_status(status)
        method_value = method.strip()
        if not method_value:
            raise ValueError("method must be non-empty")
        _validate_sha256("request_sha256", request_sha256)
        _validate_sha256("response_sha256", response_sha256)
        _validate_sha256("previous_event_sha256", previous_event_sha256)
        payload = {
            "event_id": event_id or f"acqevt-{uuid4().hex}",
            "cell_id": _cell_id(case_id, chain_value, provider_id, method_value, block_selector),
            "case_id": case_id,
            "chain": chain_value,
            "provider_id": provider_id,
            "method": method_value,
            "block_selector": block_selector,
            "observed_at_utc": observed_at_utc or _now_utc(),
            "request_sha256": request_sha256,
            "response_sha256": response_sha256,
            "raw_artifact_path": raw_artifact_path,
            "error_class": error_class,
            "error_detail": error_detail,
            "previous_event_sha256": previous_event_sha256,
        }
        hash_payload = {**payload, "status": status_value.value}
        return cls(
            **payload,
            status=status_value,
            event_sha256=canonical_json_sha256(hash_payload),
        )

    @classmethod
    def queued(
        cls,
        case_id: str | None,
        chain: str,
        provider_id: str | None,
        method: str,
        block_selector: str | None,
    ) -> "AcquisitionEvent":
        return cls.create(
            case_id=case_id,
            chain=chain,
            provider_id=provider_id,
            method=method,
            block_selector=block_selector,
            status=AcquisitionStatus.QUEUED,
        )

    @classmethod
    def from_dict(cls, mapping: dict[str, Any]) -> "AcquisitionEvent":
        if not isinstance(mapping, dict):
            raise ValueError("event row must be a JSON object")
        created = cls.create(
            case_id=mapping.get("case_id"),
            chain=mapping["chain"],
            provider_id=mapping.get("provider_id"),
            method=mapping["method"],
            block_selector=mapping.get("block_selector"),
            status=mapping["status"],
            observed_at_utc=mapping["observed_at_utc"],
            request_sha256=mapping.get("request_sha256"),
            response_sha256=mapping.get("response_sha256"),
            raw_artifact_path=mapping.get("raw_artifact_path"),
            error_class=mapping.get("error_class"),
            error_detail=mapping.get("error_detail"),
            previous_event_sha256=mapping["previous_event_sha256"],
            event_id=mapping["event_id"],
        )
        if created.cell_id != mapping["cell_id"]:
            raise ValueError("event cell_id does not match canonical event content")
        if created.event_sha256 != mapping["event_sha256"]:
            raise ValueError("event_sha256 does not match canonical event content")
        return created

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload

    def bind_previous(self, previous_event_sha256: str) -> "AcquisitionEvent":
        return self.create(
            case_id=self.case_id,
            chain=self.chain,
            provider_id=self.provider_id,
            method=self.method,
            block_selector=self.block_selector,
            status=self.status,
            observed_at_utc=self.observed_at_utc,
            request_sha256=self.request_sha256,
            response_sha256=self.response_sha256,
            raw_artifact_path=self.raw_artifact_path,
            error_class=self.error_class,
            error_detail=self.error_detail,
            previous_event_sha256=previous_event_sha256,
            event_id=self.event_id,
        )

    def transition(self, status: AcquisitionStatus | str, **overrides: Any) -> "AcquisitionEvent":
        target = validate_status_transition(self.status, status)
        next_fields = {
            "observed_at_utc": overrides.pop("observed_at_utc", None),
            "request_sha256": overrides.pop("request_sha256", self.request_sha256),
            "response_sha256": overrides.pop("response_sha256", self.response_sha256),
            "raw_artifact_path": overrides.pop("raw_artifact_path", self.raw_artifact_path),
            "error_class": overrides.pop("error_class", self.error_class),
            "error_detail": overrides.pop("error_detail", self.error_detail),
        }
        if overrides:
            raise TypeError(f"unexpected transition overrides: {sorted(overrides)}")
        return self.create(
            case_id=self.case_id,
            chain=self.chain,
            provider_id=self.provider_id,
            method=self.method,
            block_selector=self.block_selector,
            status=target,
            **next_fields,
        )
