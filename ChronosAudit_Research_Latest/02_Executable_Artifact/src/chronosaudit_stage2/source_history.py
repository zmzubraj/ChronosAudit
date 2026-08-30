from __future__ import annotations

import ast
import hashlib
import json
import os
import string
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

CHAIN_IDS = {"ethereum": 1, "bsc": 56, "base": 8453, "arbitrum": 42161}


@dataclass(frozen=True)
class SourceObservation:
    provider: str
    chain: str
    address: str
    observed_at_utc: str
    status: str
    verified_at: str | None
    exact_match: bool | None
    source_sha256: str | None
    compiler_version: str | None
    payload_sha256: str | None
    evidence_role: str
    error: str | None = None


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _fetch_json(url: str, timeout: int = 30) -> tuple[Any, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "ChronosAudit-Stage2/0.5"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()


def _source_hash_from_sourcify(payload: dict[str, Any]) -> str | None:
    # Sourcify v2 fields can include a source list or nested compilation artifacts.
    # Hash canonical JSON of only source-related fields, preserving fail-closed semantics.
    source_payload = None
    for key in ("sources", "compilation", "metadata"):
        if key in payload and payload[key] not in (None, {}, []):
            source_payload = payload[key] if source_payload is None else {"previous": source_payload, key: payload[key]}
    if source_payload is None:
        return None
    raw = json.dumps(source_payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def sourcify_contract_observation(chain: str, address: str, timeout: int = 30) -> SourceObservation:
    chain_id = CHAIN_IDS[chain]
    url = f"https://sourcify.dev/server/v2/contract/{chain_id}/{address}?fields=all"
    try:
        payload, phash = _fetch_json(url, timeout)
        match = payload.get("match") or payload.get("matchType") or payload.get("match_type")
        exact = None if match is None else "exact" in str(match).lower()
        verified_at = payload.get("verifiedAt") or payload.get("verified_at")
        compiler = payload.get("compilerVersion") or payload.get("compiler_version")
        return SourceObservation(
            provider="sourcify_v2",
            chain=chain,
            address=address.lower(),
            observed_at_utc=_now(),
            status="verified" if verified_at or payload else "not_verified",
            verified_at=verified_at,
            exact_match=exact,
            source_sha256=_source_hash_from_sourcify(payload),
            compiler_version=compiler,
            payload_sha256=phash,
            evidence_role="availability_timestamp_and_source_artifact",
        )
    except Exception as exc:
        return SourceObservation("sourcify_v2", chain, address.lower(), _now(), "error", None, None, None, None, None, "availability_timestamp_and_source_artifact", f"{type(exc).__name__}: {exc}")


def etherscan_source_observation(chain: str, address: str, api_key: str | None = None, timeout: int = 30) -> SourceObservation:
    chain_id = CHAIN_IDS[chain]
    key = api_key or os.getenv("ETHERSCAN_API_KEY", "")
    query = urllib.parse.urlencode({
        "chainid": chain_id,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": key,
    })
    url = "https://api.etherscan.io/v2/api?" + query
    try:
        payload, phash = _fetch_json(url, timeout)
        result = payload.get("result")
        row = result[0] if isinstance(result, list) and result else {}
        source = row.get("SourceCode") or ""
        source_hash = hashlib.sha256(source.encode()).hexdigest() if source else None
        return SourceObservation(
            provider="etherscan_v2",
            chain=chain,
            address=address.lower(),
            observed_at_utc=_now(),
            status="verified" if source else "not_verified",
            verified_at=None,  # getsourcecode does not provide a first-publication timestamp
            exact_match=None,
            source_sha256=source_hash,
            compiler_version=row.get("CompilerVersion") or None,
            payload_sha256=phash,
            evidence_role="independent_current_source_crosscheck_not_availability_time",
        )
    except Exception as exc:
        return SourceObservation("etherscan_v2", chain, address.lower(), _now(), "error", None, None, None, None, None, "independent_current_source_crosscheck_not_availability_time", f"{type(exc).__name__}: {exc}")


def availability_admissible(verified_at: str | None, cutoff_time: str | None) -> bool | None:
    """Return True only when a positive first-availability timestamp is <= cutoff.

    False means the supplied verification timestamp is later than cutoff; it does
    not prove that the source was unavailable elsewhere. None means evidence is
    insufficient. This asymmetry is intentional and prevents false exclusions.
    """
    if not verified_at or not cutoff_time:
        return None
    try:
        verified = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
        cutoff = datetime.fromisoformat(cutoff_time.replace("Z", "+00:00"))
    except ValueError:
        return None
    return verified <= cutoff

@dataclass(frozen=True)
class DeploymentObservation:
    provider: str
    chain: str
    address: str
    observed_at_utc: str
    status: str
    creator: str | None
    creation_tx_hash: str | None
    deployment_block: int | None
    deployment_timestamp_unix: int | None
    creation_bytecode_sha256: str | None
    payload_sha256: str | None
    evidence_role: str
    error: str | None = None


def etherscan_deployment_observation(chain: str, address: str, api_key: str | None = None, timeout: int = 30) -> DeploymentObservation:
    """Resolve a public creation record through Etherscan V2.

    This is a locator/independent metadata observation, not the final canonical
    proof. The returned tx/block must subsequently be verified against two
    independent archive-RPC providers before Stage-2 certification.
    """
    chain_id = CHAIN_IDS[chain]
    key = api_key or os.getenv("ETHERSCAN_API_KEY", "")
    query = urllib.parse.urlencode({
        "chainid": chain_id,
        "module": "contract",
        "action": "getcontractcreation",
        "contractaddresses": address,
        "apikey": key,
    })
    url = "https://api.etherscan.io/v2/api?" + query
    try:
        payload, phash = _fetch_json(url, timeout)
        result = payload.get("result")
        row = result[0] if isinstance(result, list) and result else {}
        bytecode = row.get("creationBytecode") or ""
        b_hash = hashlib.sha256(bytecode.encode()).hexdigest() if bytecode else None
        block = row.get("blockNumber")
        timestamp = row.get("timestamp")
        tx_hash = row.get("txHash") or None
        status = "located" if tx_hash and block is not None else "not_found"
        return DeploymentObservation(
            provider="etherscan_v2",
            chain=chain,
            address=address.lower(),
            observed_at_utc=_now(),
            status=status,
            creator=(row.get("contractCreator") or None),
            creation_tx_hash=tx_hash,
            deployment_block=int(block) if str(block or "").isdigit() else None,
            deployment_timestamp_unix=int(timestamp) if str(timestamp or "").isdigit() else None,
            creation_bytecode_sha256=b_hash,
            payload_sha256=phash,
            evidence_role="deployment_locator_requires_dual_archive_confirmation",
        )
    except Exception as exc:
        return DeploymentObservation("etherscan_v2", chain, address.lower(), _now(), "error", None, None, None, None, None, None, "deployment_locator_requires_dual_archive_confirmation", f"{type(exc).__name__}: {exc}")


def ingest_sourcify_export(path: str | os.PathLike, chain: str | None = None) -> list[SourceObservation]:
    """Ingest a pinned Sourcify database export from local CSV/Parquet.

    The caller is responsible for persisting the upstream export checksum/URL.
    The parser accepts common Sourcify export field names and emits normalized
    SourceObservation records. This avoids depending on today's API response for
    historical availability evidence.
    """
    import pandas as pd
    p = os.fspath(path)
    df = pd.read_parquet(p) if str(p).lower().endswith((".parquet", ".pq")) else pd.read_csv(p)
    cols = {str(c).lower(): c for c in df.columns}
    addr_col = next((cols[x] for x in ("address", "contract_address") if x in cols), None)
    chain_col = next((cols[x] for x in ("chain_id", "chainid", "chain") if x in cols), None)
    verified_col = next((cols[x] for x in ("verified_at", "verifiedat", "created_at") if x in cols), None)
    match_col = next((cols[x] for x in ("match_type", "match", "runtime_match") if x in cols), None)
    compiler_col = next((cols[x] for x in ("compiler_version", "compilerversion") if x in cols), None)
    if addr_col is None or verified_col is None:
        raise ValueError("Sourcify export must contain address and verified_at/created_at")
    chain_by_id = {str(v): k for k, v in CHAIN_IDS.items()}
    out: list[SourceObservation] = []
    for _, r in df.iterrows():
        ch = chain
        if ch is None and chain_col is not None:
            raw = str(r[chain_col])
            ch = chain_by_id.get(raw, raw.lower())
        if ch not in CHAIN_IDS:
            continue
        addr = str(r[addr_col]).lower()
        verified = None if r[verified_col] is None else str(r[verified_col])
        match = None if match_col is None else str(r[match_col])
        exact = None if not match else ("exact" in match.lower() or "perfect" in match.lower())
        canonical = json.dumps({str(k): None if getattr(r, k, None) is None else str(r[k]) for k in df.columns}, sort_keys=True, default=str).encode()
        out.append(SourceObservation(
            provider="sourcify_pinned_export", chain=ch, address=addr,
            observed_at_utc=_now(), status="verified", verified_at=verified,
            exact_match=exact, source_sha256=None,
            compiler_version=(None if compiler_col is None else str(r[compiler_col])),
            payload_sha256=hashlib.sha256(canonical).hexdigest(),
            evidence_role="pinned_append_only_source_availability_record",
        ))
    return out


def source_at_cutoff_assessment(observations: list[SourceObservation], cutoff_time: str) -> dict[str, Any]:
    """Combine source evidence without treating absence in one service as proof of absence."""
    positives = []
    late = []
    current_crosschecks = []
    errors = []
    for obs in observations:
        if obs.error or obs.status == "error":
            errors.append(obs.provider); continue
        if obs.verified_at:
            adm = availability_admissible(obs.verified_at, cutoff_time)
            (positives if adm else late).append(obs)
        elif obs.status == "verified":
            current_crosschecks.append(obs)
    status = "SOURCE_AVAILABLE_AT_CUTOFF" if positives else ("NO_POSITIVE_CUTOFF_EVIDENCE" if (late or current_crosschecks) else "INSUFFICIENT_EVIDENCE")
    return {
        "status": status,
        "cutoff_time": cutoff_time,
        "positive_timestamped_providers": sorted({o.provider for o in positives}),
        "later_timestamped_providers": sorted({o.provider for o in late}),
        "current_only_crosschecks": sorted({o.provider for o in current_crosschecks}),
        "errors": sorted(set(errors)),
        "source_admissible": bool(positives),
        "absence_proven": False,
        "reason": "positive timestamped evidence is sufficient for availability; service absence is not treated as universal non-availability",
    }


@dataclass(frozen=True)
class BulkArchiveObservation:
    provider: str
    dataset: str
    chain: str
    address: str
    block_number: int | None
    block_hash: str | None
    runtime_code_hash: str | None
    deployment_tx_hash: str | None
    observed_at_utc: str
    source_uri: str
    payload_sha256: str
    evidence_role: str = "independent_bulk_archive_corroboration"


def pinned_export_manifest(path: str | os.PathLike, provider: str, source_uri: str) -> dict[str, Any]:
    """Create immutable metadata for a downloaded public bulk export."""
    p = os.fspath(path)
    raw_hash = hashlib.sha256()
    size = 0
    with open(p, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            raw_hash.update(chunk); size += len(chunk)
    return {
        "provider": provider, "source_uri": source_uri, "local_path": p,
        "sha256": raw_hash.hexdigest(), "bytes": size, "observed_at_utc": _now(),
        "qualification_note": "Manifest proves the exact public export used; record-level semantics still require schema validation.",
    }


def _coerce_field_candidates(value: str | Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, str):
        candidates = (value,)
    else:
        candidates = tuple(str(item) for item in value)
    if not candidates or any(not candidate.strip() for candidate in candidates):
        raise ValueError("field mapping candidates must be non-empty")
    return tuple(candidate.strip() for candidate in candidates)


def _validated_field_mapping(field_mapping: dict[str, str | Iterable[str]] | None) -> dict[str, tuple[str, ...]]:
    defaults: dict[str, tuple[str, ...]] = {
        "address": ("address", "contract_address"),
        "chain": ("chain_id", "chainid", "chain"),
        "deployment_block": ("block_number", "blocknumber", "deployment_block"),
        "deployment_tx_hash": ("transaction_hash", "tx_hash", "deployment_tx_hash"),
        "deployment_time": ("timestamp", "deployment_time", "created_at"),
        "creation_type": ("creation_type",),
        "trace_proof": ("trace_proof",),
    }
    if field_mapping is None:
        return defaults

    allowed = set(defaults)
    unexpected = sorted(set(field_mapping) - allowed)
    if unexpected:
        raise ValueError(f"unsupported field mapping keys: {unexpected}")

    validated = defaults.copy()
    for key, value in field_mapping.items():
        validated[key] = _coerce_field_candidates(value)
    return validated


def _row_value(row: dict[str, Any], candidates: tuple[str, ...]) -> Any:
    lowered = {str(key).lower(): key for key in row}
    for candidate in candidates:
        matched = lowered.get(candidate.lower())
        if matched is not None:
            return row[matched]
    return None


def _normalize_export_hex_identifier(value: Any, *, expected_hex_chars: int, field_name: str) -> str:
    def _validate(text: str) -> str:
        candidate = text.strip().lower()
        if candidate.startswith("0x"):
            candidate = candidate[2:]
        if len(candidate) != expected_hex_chars or any(ch not in string.hexdigits for ch in candidate):
            raise ValueError(f"invalid {field_name}: {value}")
        return "0x" + candidate

    def _from_bytes(raw: bytes) -> str:
        try:
            decoded = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            decoded = ""
        if decoded:
            try:
                return _validate(decoded)
            except ValueError:
                pass
        return _validate(raw.hex())

    if isinstance(value, memoryview):
        return _from_bytes(value.tobytes())
    if isinstance(value, bytearray):
        return _from_bytes(bytes(value))
    if isinstance(value, bytes):
        return _from_bytes(value)

    text = str(value).strip()
    if text.startswith(("b'", 'b"')):
        try:
            literal = ast.literal_eval(text)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"invalid {field_name}: {value}") from exc
        if isinstance(literal, str):
            return _validate(literal)
        if isinstance(literal, (bytes, bytearray)):
            return _from_bytes(bytes(literal))
        raise ValueError(f"invalid {field_name}: {value}")
    return _validate(text)


def _deployment_rows_from_dataframe(df: "pd.DataFrame") -> list[dict[str, Any]]:
    return df.to_dict(orient="records")


def _deployment_rows_from_parquet(path: str, batch_size: int) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq

    rows: list[dict[str, Any]] = []
    parquet_file = pq.ParquetFile(path)
    for batch in parquet_file.iter_batches(batch_size=batch_size):
        rows.extend(batch.to_pylist())
    return rows


def ingest_sourcify_deployments_export(
    path: str | os.PathLike,
    chain: str | None = None,
    *,
    field_mapping: dict[str, str | Iterable[str]] | None = None,
    batch_size: int = 1024,
) -> list[dict[str, Any]]:
    """Normalize a pinned Sourcify contract_deployments export.

    Accepts CSV/Parquet with common deployment field spellings. This is useful for
    materializing deployment timestamps/transactions without depending on a live
    explorer response. The caller must persist the export manifest/checksum.
    """
    import pandas as pd
    p = os.fspath(path)
    mapping = _validated_field_mapping(field_mapping)
    rows = _deployment_rows_from_parquet(p, batch_size) if str(p).lower().endswith((".parquet", ".pq")) else _deployment_rows_from_dataframe(pd.read_csv(p))
    chain_by_id = {str(v): k for k, v in CHAIN_IDS.items()}
    out = []
    for row in rows:
        address_value = _row_value(row, mapping["address"])
        if address_value in (None, ""):
            raise ValueError("deployment export must contain address/contract_address")
        ch = chain
        chain_value = _row_value(row, mapping["chain"])
        if ch is None and chain_value not in (None, ""):
            raw = str(chain_value)
            ch = chain_by_id.get(raw, raw.lower())
        if ch not in CHAIN_IDS:
            continue
        canonical = json.dumps(
            {
                str(key): None if pd.isna(value) else str(value)
                for key, value in row.items()
            },
            sort_keys=True,
        ).encode()
        block_value = _row_value(row, mapping["deployment_block"])
        tx_value = _row_value(row, mapping["deployment_tx_hash"])
        time_value = _row_value(row, mapping["deployment_time"])
        creation_type = _row_value(row, mapping["creation_type"])
        trace_proof = _row_value(row, mapping["trace_proof"])
        out.append({
            "provider": "sourcify_pinned_deployments_export", "chain": ch,
            "address": _normalize_export_hex_identifier(address_value, expected_hex_chars=40, field_name="address"),
            "deployment_block": None if block_value is None or pd.isna(block_value) else int(block_value),
            "deployment_tx_hash": (
                None
                if tx_value is None or pd.isna(tx_value)
                else _normalize_export_hex_identifier(tx_value, expected_hex_chars=64, field_name="transaction hash")
            ),
            "deployment_time": None if time_value is None or pd.isna(time_value) else str(time_value),
            "creation_type": None if creation_type is None or pd.isna(creation_type) else str(creation_type),
            "trace_proof": False if trace_proof is None or pd.isna(trace_proof) else bool(trace_proof),
            "record_sha256": hashlib.sha256(canonical).hexdigest(),
        })
    return out


def source_history_qualification(observations: list[SourceObservation], cutoff_time: str, require_independent_crosscheck: bool = True) -> dict[str, Any]:
    """Strict source-at-cutoff gate with provider-family diversity."""
    base = source_at_cutoff_assessment(observations, cutoff_time)
    timestamped = sorted({o.provider for o in observations if o.verified_at and availability_admissible(o.verified_at, cutoff_time)})
    cross = sorted({o.provider for o in observations if o.status == "verified" and not o.error})
    independent = len(set(cross)) >= 2 if require_independent_crosscheck else True
    qualified = bool(timestamped) and independent
    return {**base, "timestamped_provider_count": len(timestamped), "verified_provider_count": len(set(cross)),
            "independent_crosscheck_pass": independent, "qualified": qualified,
            "qualification_reason": "requires positive timestamped availability plus an independent source/provider corroboration"}
