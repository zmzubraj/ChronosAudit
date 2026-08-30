from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .public_acquisition.counters import (
    build_review_bundle,
    make_independent_adjudication_binding_sha256,
    utc_at_or_after,
    valid_utc_review_interval,
)

REQUIRED_COLUMNS = ["case_name", "protocol_family", "primary_root_cause", "confidence", "evidence_references"]
ADJUDICATOR_COLUMNS = [
    "case_name", "final_protocol_family", "final_primary_root_cause",
    "adjudication_rationale", "evidence_references",
]
STRICT_FINALIZED_HUMAN_DECISION_STATUSES = {"reviewer_consensus", "third_adjudicator_complete"}
STRICT_FINALIZED_HUMAN_CONFIDENCE = {"high", "very_high"}


def _agreement(a: list[str], b: list[str]) -> float | None:
    if len(a) != len(b) or not a:
        return None
    return sum(x == y for x, y in zip(a, b)) / len(a)


def _kappa(a: list[str], b: list[str]) -> float | None:
    if len(a) != len(b) or not a:
        return None
    n = len(a)
    po = _agreement(a, b)
    ca, cb = Counter(a), Counter(b)
    labels = set(ca) | set(cb)
    pe = sum((ca[x] / n) * (cb[x] / n) for x in labels)
    if pe == 1:
        return 1.0
    return (po - pe) / (1 - pe)


def _gwet_ac1(a: list[str], b: list[str]) -> float | None:
    """Gwet AC1 for two nominal raters.

    The pooled category prevalence is used to estimate chance agreement. AC1 is
    reported alongside kappa because kappa can be unstable under highly skewed
    category prevalence.
    """
    if len(a) != len(b) or not a:
        return None
    labels = sorted(set(a) | set(b))
    q = len(labels)
    po = _agreement(a, b)
    if q <= 1:
        return 1.0
    n = len(a)
    pooled = {lab: (a.count(lab) + b.count(lab)) / (2 * n) for lab in labels}
    pe = sum(p * (1 - p) for p in pooled.values()) / (q - 1)
    if pe >= 1:
        return 1.0
    return (po - pe) / (1 - pe)


def _bootstrap_ci(a: list[str], b: list[str], stat, n_boot: int = 2000, seed: int = 20260807) -> tuple[float | None, float | None]:
    if len(a) != len(b) or len(a) < 2:
        return (None, None)
    rng = np.random.default_rng(seed)
    vals = []
    a_arr = np.array(a, dtype=object)
    b_arr = np.array(b, dtype=object)
    for _ in range(n_boot):
        idx = rng.integers(0, len(a), len(a))
        value = stat(a_arr[idx].tolist(), b_arr[idx].tolist())
        if value is not None and np.isfinite(value):
            vals.append(float(value))
    if not vals:
        return (None, None)
    return (float(np.quantile(vals, 0.025)), float(np.quantile(vals, 0.975)))


def validate_review_file(path: Path) -> list[str]:
    df = pd.read_csv(path)
    errors = []
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        return [f"missing_columns:{','.join(missing)}"]
    if df.case_name.duplicated().any():
        errors.append("duplicate_case_name")
    if df[REQUIRED_COLUMNS].isna().any().any():
        errors.append("missing_required_values")
    return errors


def validate_adjudicator_file(path: Path) -> list[str]:
    df = pd.read_csv(path)
    missing = [c for c in ADJUDICATOR_COLUMNS if c not in df.columns]
    if missing:
        return [f"missing_columns:{','.join(missing)}"]
    errors = []
    if df.case_name.duplicated().any():
        errors.append("duplicate_case_name")
    if df[ADJUDICATOR_COLUMNS].isna().any().any():
        errors.append("missing_required_values")
    return errors


def create_blinded_reviewer_packets(source: Path, reviewer_a: Path, reviewer_b: Path) -> dict[str, Any]:
    """Create reviewer packets without automated protocol/mechanism candidates.

    Only raw case/incident evidence is exposed before the independent labels are
    frozen, preventing anchoring on the machine-generated candidate taxonomy.
    """
    src = pd.read_csv(source)
    preferred = [
        "case_name", "incident_name", "chain", "target_contract_address",
        "incident_date", "incident_reference", "transaction_hash_hints",
        "incident_record_sha256", "source_snapshot_sha256",
    ]
    visible = [c for c in preferred if c in src.columns]
    if "case_name" not in visible:
        raise ValueError("source must contain case_name")
    base = src[visible].copy()
    packets = build_review_bundle(
        base.assign(source_manifest_sha256=src.get("source_snapshot_sha256", "")),
        packet_type="positive_case_review_packets",
        blinding_seed=str(source),
    )
    for out_path in (reviewer_a, reviewer_b):
        out = base.copy()
        for col in REQUIRED_COLUMNS[1:]:
            out[col] = ""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out.to_csv(out_path, index=False)
    return {
        "status": "blinded_packets_created",
        "cases": len(base),
        "visible_evidence_columns": visible,
        "positive_case_review_packets": len(packets),
    }


def finalized_independent_human_adjudications(frame_or_path: pd.DataFrame | Path) -> pd.DataFrame:
    frame = pd.read_csv(frame_or_path) if isinstance(frame_or_path, Path) else frame_or_path.copy()
    required = {
        "case_name",
        "adjudication_status",
        "final_decision_sha256",
        "final_decision_input_binding_sha256",
        "reviewer_a_identity",
        "reviewer_a_owner",
        "reviewer_a_conflict_clear",
        "reviewer_a_confidence",
        "reviewer_a_started_at_utc",
        "reviewer_a_completed_at_utc",
        "reviewer_a_packet_sha256",
        "reviewer_a_decision_sha256",
        "reviewer_b_identity",
        "reviewer_b_owner",
        "reviewer_b_conflict_clear",
        "reviewer_b_confidence",
        "reviewer_b_started_at_utc",
        "reviewer_b_completed_at_utc",
        "reviewer_b_packet_sha256",
        "reviewer_b_decision_sha256",
        "review_agreement_status",
        "decision_schema_valid",
        "decision_hash_bound",
        "third_adjudicator_identity",
        "third_adjudicator_owner",
        "third_adjudicator_conflict_clear",
        "third_adjudicator_confidence",
        "third_adjudicator_started_at_utc",
        "third_adjudicator_completed_at_utc",
        "third_adjudicator_packet_sha256",
        "third_adjudicator_decision_sha256",
        "final_decision_completed_at_utc",
    }
    missing = sorted(required - set(frame.columns))
    if missing:
        return pd.DataFrame(columns=list(required) + ["independent_human_adjudication"])

    qualified = frame.copy()
    qualified["independent_human_adjudication"] = qualified.apply(
        lambda row: (
            str(row["adjudication_status"]).strip().lower() in STRICT_FINALIZED_HUMAN_DECISION_STATUSES
            and str(row["reviewer_a_identity"]).strip() not in {"", "AI", "PUBLIC", "PUBLIC_LABEL", "SAME_OWNER"}
            and str(row["reviewer_b_identity"]).strip() not in {"", "AI", "PUBLIC", "PUBLIC_LABEL", "SAME_OWNER"}
            and str(row["reviewer_a_identity"]).strip() != str(row["reviewer_b_identity"]).strip()
            and str(row["reviewer_a_owner"]).strip() not in {"", "SAME_OWNER"}
            and str(row["reviewer_b_owner"]).strip() not in {"", "SAME_OWNER"}
            and str(row["reviewer_a_owner"]).strip() != str(row["reviewer_b_owner"]).strip()
            and bool(row["reviewer_a_conflict_clear"])
            and bool(row["reviewer_b_conflict_clear"])
            and str(row["reviewer_a_confidence"]).strip().lower() in STRICT_FINALIZED_HUMAN_CONFIDENCE
            and str(row["reviewer_b_confidence"]).strip().lower() in STRICT_FINALIZED_HUMAN_CONFIDENCE
            and valid_utc_review_interval(row["reviewer_a_started_at_utc"], row["reviewer_a_completed_at_utc"])
            and valid_utc_review_interval(row["reviewer_b_started_at_utc"], row["reviewer_b_completed_at_utc"])
            and isinstance(row["reviewer_a_packet_sha256"], str)
            and len(row["reviewer_a_packet_sha256"]) == 64
            and all(ch in "0123456789abcdef" for ch in row["reviewer_a_packet_sha256"].lower())
            and isinstance(row["reviewer_b_packet_sha256"], str)
            and len(row["reviewer_b_packet_sha256"]) == 64
            and all(ch in "0123456789abcdef" for ch in row["reviewer_b_packet_sha256"].lower())
            and isinstance(row["reviewer_a_decision_sha256"], str)
            and len(row["reviewer_a_decision_sha256"]) == 64
            and all(ch in "0123456789abcdef" for ch in row["reviewer_a_decision_sha256"].lower())
            and isinstance(row["reviewer_b_decision_sha256"], str)
            and len(row["reviewer_b_decision_sha256"]) == 64
            and all(ch in "0123456789abcdef" for ch in row["reviewer_b_decision_sha256"].lower())
            and (
                (
                    str(row["review_agreement_status"]).strip() == "REVIEWER_CONSENSUS"
                    and str(row["third_adjudicator_identity"]).strip() == ""
                    and str(row["third_adjudicator_owner"]).strip() == ""
                    and str(row["third_adjudicator_started_at_utc"]).strip() == ""
                    and str(row["third_adjudicator_completed_at_utc"]).strip() == ""
                    and str(row["third_adjudicator_packet_sha256"]).strip() == ""
                    and str(row["third_adjudicator_decision_sha256"]).strip() == ""
                )
                or (
                    str(row["review_agreement_status"]).strip() == "THIRD_ADJUDICATOR_COMPLETE"
                    and str(row["third_adjudicator_identity"]).strip() not in {"", "AI", "PUBLIC", "PUBLIC_LABEL", "SAME_OWNER"}
                    and str(row["third_adjudicator_owner"]).strip() not in {"", "SAME_OWNER"}
                    and str(row["third_adjudicator_owner"]).strip()
                    not in {str(row["reviewer_a_owner"]).strip(), str(row["reviewer_b_owner"]).strip()}
                    and bool(row["third_adjudicator_conflict_clear"])
                    and str(row["third_adjudicator_confidence"]).strip().lower() in STRICT_FINALIZED_HUMAN_CONFIDENCE
                    and valid_utc_review_interval(
                        row["third_adjudicator_started_at_utc"], row["third_adjudicator_completed_at_utc"]
                    )
                    and isinstance(row["third_adjudicator_packet_sha256"], str)
                    and len(row["third_adjudicator_packet_sha256"]) == 64
                    and all(ch in "0123456789abcdef" for ch in row["third_adjudicator_packet_sha256"].lower())
                    and isinstance(row["third_adjudicator_decision_sha256"], str)
                    and len(row["third_adjudicator_decision_sha256"]) == 64
                    and all(ch in "0123456789abcdef" for ch in row["third_adjudicator_decision_sha256"].lower())
                )
            )
            and isinstance(row["final_decision_sha256"], str)
            and len(row["final_decision_sha256"]) == 64
            and all(ch in "0123456789abcdef" for ch in row["final_decision_sha256"].lower())
            and str(row["final_decision_input_binding_sha256"]).strip().lower()
            == make_independent_adjudication_binding_sha256(row).lower()
            and utc_at_or_after(
                row["final_decision_completed_at_utc"],
                row["reviewer_a_completed_at_utc"],
                row["reviewer_b_completed_at_utc"],
            )
            and (
                str(row["review_agreement_status"]).strip() != "THIRD_ADJUDICATOR_COMPLETE"
                or utc_at_or_after(
                    row["final_decision_completed_at_utc"], row["third_adjudicator_completed_at_utc"]
                )
            )
            and bool(row["decision_schema_valid"])
            and bool(row["decision_hash_bound"])
        ),
        axis=1,
    )
    return qualified


def adjudicate_reviews(reviewer_a: Path, reviewer_b: Path, output: Path, adjudicator: Path | None = None) -> dict[str, Any]:
    errors = {"reviewer_a": validate_review_file(reviewer_a), "reviewer_b": validate_review_file(reviewer_b)}
    if any(errors.values()):
        return {"status": "blocked_invalid_review_files", "errors": errors}

    a = pd.read_csv(reviewer_a).add_suffix("_a").rename(columns={"case_name_a": "case_name"})
    b = pd.read_csv(reviewer_b).add_suffix("_b").rename(columns={"case_name_b": "case_name"})
    m = a.merge(b, on="case_name", how="outer", indicator=True)
    if (m._merge != "both").any():
        return {"status": "blocked_case_set_mismatch", "mismatch_rows": int((m._merge != "both").sum())}
    m = m.drop(columns=["_merge"])
    m["protocol_agree"] = m.protocol_family_a == m.protocol_family_b
    m["mechanism_agree"] = m.primary_root_cause_a == m.primary_root_cause_b
    m["requires_adjudication"] = ~(m.protocol_agree & m.mechanism_agree)

    # Consensus labels are usable without adjudication only when both reviewers agree.
    m["final_protocol_family"] = m.protocol_family_a.where(m.protocol_agree)
    m["final_primary_root_cause"] = m.primary_root_cause_a.where(m.mechanism_agree)
    m["adjudication_status"] = np.where(m.requires_adjudication, "pending_third_adjudicator", "reviewer_consensus")
    m["adjudication_rationale"] = np.where(m.requires_adjudication, "", "reviewers_agree")
    m["adjudicator_evidence_references"] = ""

    disagreements = set(m.loc[m.requires_adjudication, "case_name"].astype(str))
    if adjudicator is not None:
        adj_errors = validate_adjudicator_file(adjudicator)
        if adj_errors:
            return {"status": "blocked_invalid_adjudicator_file", "errors": adj_errors}
        adj = pd.read_csv(adjudicator)
        provided = set(adj.case_name.astype(str))
        missing = sorted(disagreements - provided)
        unexpected = sorted(provided - disagreements)
        if missing or unexpected:
            return {
                "status": "blocked_adjudicator_case_set_mismatch",
                "missing_disagreements": missing,
                "unexpected_cases": unexpected,
            }
        adj = adj.set_index("case_name")
        for idx, row in m[m.requires_adjudication].iterrows():
            ar = adj.loc[str(row.case_name)]
            m.at[idx, "final_protocol_family"] = ar.final_protocol_family
            m.at[idx, "final_primary_root_cause"] = ar.final_primary_root_cause
            m.at[idx, "adjudication_status"] = "third_adjudicator_complete"
            m.at[idx, "adjudication_rationale"] = ar.adjudication_rationale
            m.at[idx, "adjudicator_evidence_references"] = ar.evidence_references

    m["review_pair_sha256"] = m.apply(
        lambda r: hashlib.sha256(json.dumps(r.fillna("").to_dict(), sort_keys=True, default=str).encode()).hexdigest(), axis=1
    )
    m["final_decision_sha256"] = m.apply(
        lambda r: hashlib.sha256(json.dumps({
            "case_name": r.case_name,
            "final_protocol_family": r.final_protocol_family if pd.notna(r.final_protocol_family) else "",
            "final_primary_root_cause": r.final_primary_root_cause if pd.notna(r.final_primary_root_cause) else "",
            "adjudication_status": r.adjudication_status,
            "adjudication_rationale": r.adjudication_rationale,
            "evidence": r.adjudicator_evidence_references,
        }, sort_keys=True, default=str).encode()).hexdigest(), axis=1
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    m.to_csv(output, index=False)

    pa = _agreement(m.protocol_family_a.astype(str).tolist(), m.protocol_family_b.astype(str).tolist())
    ma = _agreement(m.primary_root_cause_a.astype(str).tolist(), m.primary_root_cause_b.astype(str).tolist())
    kp = _kappa(m.protocol_family_a.astype(str).tolist(), m.protocol_family_b.astype(str).tolist())
    km = _kappa(m.primary_root_cause_a.astype(str).tolist(), m.primary_root_cause_b.astype(str).tolist())
    gp = _gwet_ac1(m.protocol_family_a.astype(str).tolist(), m.protocol_family_b.astype(str).tolist())
    gm = _gwet_ac1(m.primary_root_cause_a.astype(str).tolist(), m.primary_root_cause_b.astype(str).tolist())
    kp_ci = _bootstrap_ci(m.protocol_family_a.astype(str).tolist(), m.protocol_family_b.astype(str).tolist(), _kappa)
    km_ci = _bootstrap_ci(m.primary_root_cause_a.astype(str).tolist(), m.primary_root_cause_b.astype(str).tolist(), _kappa)
    gp_ci = _bootstrap_ci(m.protocol_family_a.astype(str).tolist(), m.protocol_family_b.astype(str).tolist(), _gwet_ac1)
    gm_ci = _bootstrap_ci(m.primary_root_cause_a.astype(str).tolist(), m.primary_root_cause_b.astype(str).tolist(), _gwet_ac1)

    pending = int((m.adjudication_status == "pending_third_adjudicator").sum())
    status = "adjudication_complete" if pending == 0 else "review_pair_complete_requires_adjudication"
    return {
        "status": status,
        "cases": len(m),
        "protocol_raw_agreement": pa,
        "mechanism_raw_agreement": ma,
        "protocol_kappa": kp,
        "protocol_kappa_95ci": kp_ci,
        "mechanism_kappa": km,
        "mechanism_kappa_95ci": km_ci,
        "protocol_gwet_ac1": gp,
        "protocol_gwet_ac1_95ci": gp_ci,
        "mechanism_gwet_ac1": gm,
        "mechanism_gwet_ac1_95ci": gm_ci,
        "disagreements": int(m.requires_adjudication.sum()),
        "pending_adjudication": pending,
    }


def _krippendorff_alpha_nominal(a: list[str], b: list[str]) -> float | None:
    """Krippendorff alpha for two complete nominal raters.

    Implemented directly so the artifact does not require an additional runtime
    dependency. Missing labels must be removed before calling this function.
    """
    if len(a) != len(b) or not a:
        return None
    pairs = list(zip(a, b))
    do = sum(x != y for x, y in pairs) / len(pairs)
    counts = Counter(a + b)
    n = 2 * len(a)
    if n <= 1:
        return 1.0
    # Expected nominal disagreement under the pooled marginal distribution.
    de = 1.0 - sum((c / n) ** 2 for c in counts.values())
    if de == 0:
        return 1.0 if do == 0 else None
    return 1.0 - do / de


def external_corroboration_table(final_reviews: Path, external_labels: Path, output: Path,
                                 external_source_id: str,
                                 external_source_independent: bool = True,
                                 incident_source_lineage_independent: bool = False) -> dict[str, Any]:
    """Compare frozen ChronosAudit decisions with a public third-party label set.

    This function deliberately distinguishes curator independence from incident-
    source-lineage independence. A benchmark derived from DeFiHackLabs can be an
    independent curation effort without being an independent incident source.
    It therefore strengthens triangulation but cannot silently satisfy the two-
    reviewer ChronosAudit gate.
    """
    final = pd.read_csv(final_reviews)
    ext = pd.read_csv(external_labels)
    required_final = {"case_name", "final_protocol_family", "final_primary_root_cause"}
    required_ext = {"case_name", "external_protocol_family", "external_primary_root_cause", "external_evidence_references"}
    if not required_final.issubset(final.columns):
        raise ValueError(f"final_reviews missing {sorted(required_final-set(final.columns))}")
    if not required_ext.issubset(ext.columns):
        raise ValueError(f"external_labels missing {sorted(required_ext-set(ext.columns))}")
    m = final[list(required_final)].merge(ext[list(required_ext)], on="case_name", how="inner")
    m["protocol_corroborates"] = m.final_protocol_family.astype(str) == m.external_protocol_family.astype(str)
    m["mechanism_corroborates"] = m.final_primary_root_cause.astype(str) == m.external_primary_root_cause.astype(str)
    m["external_source_id"] = external_source_id
    m["external_curator_independent"] = bool(external_source_independent)
    m["incident_source_lineage_independent"] = bool(incident_source_lineage_independent)
    m["corroboration_grade"] = np.where(
        m.protocol_corroborates & m.mechanism_corroborates,
        "third_party_label_corroboration",
        "requires_external_discrepancy_review",
    )
    m["corroboration_sha256"] = m.apply(lambda r: hashlib.sha256(json.dumps(r.fillna("").to_dict(), sort_keys=True, default=str).encode()).hexdigest(), axis=1)
    output.parent.mkdir(parents=True, exist_ok=True); m.to_csv(output, index=False)
    return {
        "status": "external_corroboration_complete",
        "matched_cases": len(m),
        "protocol_agreement": float(m.protocol_corroborates.mean()) if len(m) else None,
        "mechanism_agreement": float(m.mechanism_corroborates.mean()) if len(m) else None,
        "external_curator_independent": bool(external_source_independent),
        "incident_source_lineage_independent": bool(incident_source_lineage_independent),
        "satisfies_internal_dual_review_gate": False,
    }


def review_reliability_summary(reviewer_a: Path, reviewer_b: Path) -> dict[str, Any]:
    """Return a richer reliability panel without adjudicating or modifying labels."""
    if validate_review_file(reviewer_a) or validate_review_file(reviewer_b):
        raise ValueError("invalid review files")
    a = pd.read_csv(reviewer_a).sort_values("case_name")
    b = pd.read_csv(reviewer_b).sort_values("case_name")
    if a.case_name.tolist() != b.case_name.tolist():
        raise ValueError("case-set mismatch")
    out = {}
    for prefix, col in [("protocol", "protocol_family"), ("mechanism", "primary_root_cause")]:
        x = a[col].astype(str).tolist(); y = b[col].astype(str).tolist()
        out[f"{prefix}_raw_agreement"] = _agreement(x, y)
        out[f"{prefix}_cohen_kappa"] = _kappa(x, y)
        out[f"{prefix}_gwet_ac1"] = _gwet_ac1(x, y)
        out[f"{prefix}_krippendorff_alpha_nominal"] = _krippendorff_alpha_nominal(x, y)
    out["cases"] = len(a)
    return out


def reviewer_independence_check(metadata_a: Path, metadata_b: Path, adjudicator_metadata: Path | None = None) -> dict[str, Any]:
    """Validate reviewer/adjudicator identity independence from JSON sidecars.

    Required keys: reviewer_id, organization, conflict_statement, completed_at_utc.
    This does not manufacture independence; it creates an auditable gate that fails
    when identities collide or conflicts are undeclared.
    """
    required = {"reviewer_id", "organization", "conflict_statement", "completed_at_utc"}
    docs = []
    for role, path in [("reviewer_a", metadata_a), ("reviewer_b", metadata_b), ("adjudicator", adjudicator_metadata)]:
        if path is None:
            continue
        try:
            obj = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:
            return {"status": "blocked_invalid_metadata", "role": role, "error": f"{type(exc).__name__}:{exc}"}
        missing = sorted(required - set(obj))
        if missing:
            return {"status": "blocked_invalid_metadata", "role": role, "missing": missing}
        docs.append((role, obj))
    ids = [str(x[1]["reviewer_id"]).strip() for x in docs]
    conflicts = [x[0] for x in docs if str(x[1]["conflict_statement"]).strip().lower() in {"", "none provided", "unknown"}]
    duplicated = sorted({x for x in ids if ids.count(x) > 1})
    status = "independence_metadata_pass" if not duplicated and not conflicts and len(docs) >= 2 else "blocked_independence_metadata"
    return {
        "status": status,
        "roles": [x[0] for x in docs],
        "reviewer_ids_sha256": [hashlib.sha256(x.encode()).hexdigest() for x in ids],
        "organizations": [str(x[1]["organization"]) for x in docs],
        "duplicate_reviewer_ids": duplicated,
        "undeclared_conflicts": conflicts,
        "note": "Different organizations strengthen independence but are not automatically required; unique reviewers and declared conflicts are mandatory.",
    }


def same_case_review_gate(final_reviews: Path, expected_cases: Path, min_confidence: float = 0.5) -> dict[str, Any]:
    """Strict same-case human-review completion gate.

    External published labels can be used for corroboration elsewhere but cannot
    satisfy this gate unless they are joined casewise and explicitly imported as
    reviewer observations with provenance.
    """
    r = pd.read_csv(final_reviews)
    e = pd.read_csv(expected_cases)
    if "case_name" not in r or "case_name" not in e:
        return {"status": "blocked_missing_case_name"}
    expected = set(e.case_name.astype(str))
    got = set(r.case_name.astype(str))
    missing = sorted(expected - got)
    extras = sorted(got - expected)
    required = {"final_protocol_family", "final_primary_root_cause", "adjudication_status"}
    missing_cols = sorted(required - set(r.columns))
    if missing_cols:
        return {"status": "blocked_missing_columns", "missing_columns": missing_cols}
    complete_mask = (
        r.final_protocol_family.astype(str).str.strip().ne("") &
        r.final_primary_root_cause.astype(str).str.strip().ne("") &
        r.adjudication_status.astype(str).isin(["reviewer_consensus", "third_adjudicator_complete"])
    )
    completed = int(complete_mask.sum())
    return {
        "status": "pass" if not missing and not extras and completed == len(expected) else "blocked_incomplete_same_case_review",
        "expected_cases": len(expected), "completed_cases": completed,
        "missing_cases": len(missing), "unexpected_cases": len(extras),
        "note": "Published external taxonomies are corroboration, not substitutes for same-case blinded labels.",
    }
