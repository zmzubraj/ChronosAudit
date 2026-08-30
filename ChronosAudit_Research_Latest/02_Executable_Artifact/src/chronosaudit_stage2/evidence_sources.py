from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

# These overrides resolve the small number of repeated/aliased DeFiHackLabs file
# names. They are frozen, human-auditable decisions keyed by incident date.
# The date is checked against the parsed historical index; no evidence fields are
# invented by the override itself.
CASE_INCIDENT_DATE_OVERRIDES: dict[str, str] = {
    "bzx": "20200912",
    "audius": "20220723",
    "silo_finance": "20230427",
    "lw": "20230512",
    "peapodsfinance": "20240129",
    "atm": "20240401",
    "moonwell": "20251104",
    "sheepfarm2": "20221116",
    "wiselending03": "20240112",
    "bzx2": "20231202",
    "lw2": "20240708",
    "miner": "20240215",
    "bankroll_network": "20250619",
    "xst_2": "20220810",
    "res_2": "20221006",
    "conic_2": "20230721",
}

SOURCE_URLS = {
    "README_current.md": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/README.md",
    "2025.md": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2025/README.md",
    "2024.md": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2024/README.md",
    "2023.md": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2023/README.md",
    "2022.md": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2022/README.md",
    "2021.md": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2021/README.md",
}

CHAIN_HOST_MAP = {
    "etherscan.io": "ethereum",
    "bscscan.com": "bsc",
    "basescan.org": "base",
    "arbiscan.io": "arbitrum",
}

HEADING_RE = re.compile(r"^###\s+(20\d{6})\s+(.+?)(?:\s+-\s+(.+))?\s*$", re.MULTILINE)
CONTRACT_LINK_RE = re.compile(
    r"\[([^\]]+)\]\((?:\.\./\.\./)?(src/test/[^\)]+)\)", re.IGNORECASE
)
CONTRACT_PATH_RE = re.compile(
    r"(?:\./)?(src/test/[0-9]{4}-[0-9]{2}/[A-Za-z0-9_./-]+(?:\.sol)?)",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\)\]>]+")
LOSS_RE = re.compile(r"^###\s+Lost:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
TX_HASH_RE = re.compile(r"0x[a-fA-F0-9]{64}")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _stem_variants(label: str, path: str) -> set[str]:
    values = {label, Path(path).name, Path(path).stem}
    out: set[str] = set()
    for value in values:
        n = _norm(value)
        for suffix in ("exp", "poc", "test"):
            if n.endswith(suffix):
                n = n[: -len(suffix)]
        if n:
            out.add(n)
    return out


def _infer_chain(urls: list[str]) -> str | None:
    found: set[str] = set()
    for url in urls:
        low = url.lower()
        for host, chain in CHAIN_HOST_MAP.items():
            if host in low:
                found.add(chain)
    return next(iter(found)) if len(found) == 1 else None


def _extract_tx_hashes(urls: list[str]) -> list[str]:
    out: list[str] = []
    for url in urls:
        if "/tx/" not in url.lower():
            continue
        match = TX_HASH_RE.search(url)
        if match:
            out.append(match.group(0).lower())
    return sorted(set(out))


def _parse_defihacklabs_text(
    text: str,
    *,
    source_name: str,
    source_url: str,
    source_sha256: str,
) -> list["IncidentEntry"]:
    matches = list(HEADING_RE.finditer(text))
    rows: list[IncidentEntry] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[start:end]
        date_compact = match.group(1)
        title = match.group(2).strip().lstrip("- ").strip()
        mechanism = (match.group(3) or "").strip()
        linked = CONTRACT_LINK_RE.findall(block)
        contract_paths = [p for _, p in linked]
        contract_labels = [label for label, _ in linked]
        for p in CONTRACT_PATH_RE.findall(block):
            if p not in contract_paths:
                contract_paths.append(p)
        basename_keys: set[str] = set()
        for label, p in linked:
            basename_keys |= _stem_variants(label, p)
        for p in contract_paths:
            basename_keys |= _stem_variants(Path(p).name, p)
        urls = [u.rstrip(".,;") for u in URL_RE.findall(block)]
        loss_match = LOSS_RE.search(block)
        rows.append(
            IncidentEntry(
                date_compact=date_compact,
                incident_date=f"{date_compact[:4]}-{date_compact[4:6]}-{date_compact[6:]}",
                title=title,
                mechanism_raw=mechanism,
                loss_text=loss_match.group(1).strip() if loss_match else None,
                source_file=source_name,
                source_url=source_url,
                source_sha256=source_sha256,
                block_sha256=_sha256_bytes(block.encode("utf-8")),
                contract_paths=tuple(sorted(set(contract_paths))),
                contract_labels=tuple(sorted(set(contract_labels))),
                basename_keys=tuple(sorted(basename_keys)),
                references=tuple(sorted(set(urls))),
                tx_hashes=tuple(_extract_tx_hashes(urls)),
                inferred_chain=_infer_chain(urls),
            )
        )
    return rows


@dataclass(frozen=True)
class IncidentEntry:
    date_compact: str
    incident_date: str
    title: str
    mechanism_raw: str
    loss_text: str | None
    source_file: str
    source_url: str
    source_sha256: str
    block_sha256: str
    contract_paths: tuple[str, ...]
    contract_labels: tuple[str, ...]
    basename_keys: tuple[str, ...]
    references: tuple[str, ...]
    tx_hashes: tuple[str, ...]
    inferred_chain: str | None

    def as_dict(self) -> dict[str, Any]:
        row = self.__dict__.copy()
        for key in ("contract_paths", "contract_labels", "basename_keys", "references", "tx_hashes"):
            row[key] = json.dumps(list(row[key]), sort_keys=True)
        return row


def parse_defihacklabs_snapshot(path: Path) -> list[IncidentEntry]:
    return parse_defihacklabs_snapshot_bytes(
        path.read_bytes(),
        source_name=path.name,
        source_url=SOURCE_URLS.get(path.name, ""),
    )


def parse_defihacklabs_snapshot_bytes(
    raw_bytes: bytes,
    *,
    source_name: str,
    source_url: str,
) -> list[IncidentEntry]:
    text = raw_bytes.decode("utf-8", errors="replace")
    source_hash = _sha256_bytes(raw_bytes)
    return _parse_defihacklabs_text(
        text,
        source_name=source_name,
        source_url=source_url,
        source_sha256=source_hash,
    )


def build_incident_index(snapshot_dir: Path) -> tuple[list[IncidentEntry], pd.DataFrame]:
    entries: list[IncidentEntry] = []
    provenance_rows: list[dict[str, Any]] = []
    for path in sorted(snapshot_dir.glob("*.md")):
        parsed = parse_defihacklabs_snapshot(path)
        entries.extend(parsed)
        provenance_rows.append(
            {
                "source_name": "DeFiHackLabs",
                "local_file": str(path.name),
                "source_url": SOURCE_URLS.get(path.name, ""),
                "sha256": _sha256_file(path),
                "records_parsed": len(parsed),
                "license": "Apache-2.0",
                "role": "evaluator_only_incident_evidence",
                "acquisition_note": "Frozen public snapshot; hashes bind the exact bytes used by this artifact.",
            }
        )
    return entries, pd.DataFrame(provenance_rows)


def _candidate_entries(case_name: str, entries: list[IncidentEntry]) -> list[IncidentEntry]:
    key = _norm(case_name)
    return [e for e in entries if key in set(e.basename_keys)]


def _fallback_candidates(case_name: str, entries: list[IncidentEntry]) -> list[IncidentEntry]:
    # Deliberately conservative. It only allows exact normalized title containment;
    # ambiguous results are resolved solely by the frozen date override table.
    key = _norm(case_name)
    return [e for e in entries if key and (key in _norm(e.title) or _norm(e.title) in key)]


def match_case(case_name: str, entries: list[IncidentEntry]) -> tuple[IncidentEntry | None, str, list[str]]:
    exact = _candidate_entries(case_name, entries)
    override = CASE_INCIDENT_DATE_OVERRIDES.get(case_name)
    candidates = exact if exact else _fallback_candidates(case_name, entries)
    if override:
        dated = [e for e in entries if e.date_compact == override and (e in candidates or case_name in CASE_INCIDENT_DATE_OVERRIDES)]
        # For aliases without basename equality, constrain by title/basename resemblance.
        if len(dated) > 1:
            key = _norm(case_name)
            dated = [e for e in dated if key in _norm(e.title) or _norm(e.title) in key or any(key in b or b in key for b in e.basename_keys)]
        if len(dated) == 1:
            return dated[0], "frozen_date_override", [e.date_compact for e in candidates]
    if len(exact) == 1:
        return exact[0], "exact_contract_basename", [exact[0].date_compact]
    if len(candidates) == 1:
        return candidates[0], "normalized_title_fallback", [candidates[0].date_compact]
    return None, "ambiguous_or_missing", sorted({e.date_compact for e in candidates})


def enrich_scone_incidents(
    scone_csv: Path,
    snapshot_dir: Path,
    output_csv: Path,
    provenance_csv: Path,
    matching_audit_csv: Path,
) -> dict[str, Any]:
    scone = pd.read_csv(scone_csv)
    entries, provenance = build_incident_index(snapshot_dir)
    rows: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    for _, case in scone.iterrows():
        case_name = str(case["case_name"])
        entry, method, candidate_dates = match_case(case_name, entries)
        audits.append(
            {
                "case_name": case_name,
                "match_status": "matched" if entry else "unresolved",
                "match_method": method,
                "candidate_dates": json.dumps(candidate_dates),
                "selected_date": entry.incident_date if entry else "",
            }
        )
        if not entry:
            rows.append(
                {
                    "case_name": case_name,
                    "incident_date": pd.NA,
                    "incident_name": pd.NA,
                    "mechanism_raw": pd.NA,
                    "incident_contract_path": pd.NA,
                    "incident_chain": pd.NA,
                    "source_url": pd.NA,
                    "source_status": "unresolved_fail_closed",
                    "source_snapshot_sha256": pd.NA,
                    "incident_record_sha256": pd.NA,
                    "incident_reference_urls": "[]",
                    "incident_tx_hashes": "[]",
                    "incident_loss_text": pd.NA,
                    "match_method": method,
                }
            )
            continue
        primary_path = entry.contract_paths[0] if entry.contract_paths else ""
        rows.append(
            {
                "case_name": case_name,
                "incident_date": entry.incident_date,
                "incident_name": entry.title,
                "mechanism_raw": entry.mechanism_raw,
                "incident_contract_path": primary_path,
                "incident_chain": entry.inferred_chain or str(case.get("chain", "")),
                "source_url": entry.source_url,
                "source_status": "frozen_public_source_hashed",
                "source_snapshot_sha256": entry.source_sha256,
                "incident_record_sha256": entry.block_sha256,
                "incident_reference_urls": json.dumps(list(entry.references), sort_keys=True),
                "incident_tx_hashes": json.dumps(list(entry.tx_hashes), sort_keys=True),
                "incident_loss_text": entry.loss_text,
                "match_method": method,
            }
        )
    out = pd.DataFrame(rows)
    audit = pd.DataFrame(audits)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(output_csv, index=False)
    provenance.to_csv(provenance_csv, index=False)
    audit.to_csv(matching_audit_csv, index=False)
    matched = int(out["incident_date"].notna().sum())
    ambiguous = int((audit["match_status"] != "matched").sum())
    method_counts = audit["match_method"].value_counts().to_dict()
    return {
        "built_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "scone_rows": int(len(scone)),
        "incident_index_rows": int(len(entries)),
        "matched_rows": matched,
        "coverage": matched / len(scone) if len(scone) else 0.0,
        "unresolved_rows": ambiguous,
        "match_methods": {str(k): int(v) for k, v in method_counts.items()},
        "snapshot_files": int(len(provenance)),
        "decision": "INCIDENT_EVIDENCE_INDEX_COMPLETE" if ambiguous == 0 else "INCIDENT_EVIDENCE_INDEX_PARTIAL_FAIL_CLOSED",
    }
