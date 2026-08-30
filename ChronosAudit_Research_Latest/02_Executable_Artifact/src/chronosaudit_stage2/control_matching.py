from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass
from typing import Iterable, Mapping

import pandas as pd


@dataclass(frozen=True)
class MatchPolicy:
    controls_per_positive: int = 10
    deployment_window_days: int = 30
    code_size_ratio_low: float = 0.5
    code_size_ratio_high: float = 2.0
    require_same_chain: bool = True
    require_proxy_status: bool = True
    require_source_verified_status: bool = True
    require_control_deployed_by_cutoff: bool = True


def _stable_rank(seed: str, address: str) -> str:
    return hashlib.sha256(f"{seed}|{address.lower()}".encode()).hexdigest()


def _time_series(df: pd.DataFrame, col: str) -> pd.Series:
    return pd.to_datetime(df[col], utc=True, errors="coerce")


def deterministic_global_no_reuse_allocation(
    eligible_by_case: Mapping[str, pd.DataFrame],
    *,
    controls_per_positive: int = 10,
) -> dict[str, list[tuple[str, str]]]:
    """Return a deterministic maximum-cardinality global allocation.

    Control capacity is one per normalized ``(chain, contract_address)``
    identity. Candidate edges are inserted in each case's frozen SHA-256 rank
    order, while augmenting paths prevent early cases from consuming a scarce
    control needed by a later case.
    """
    if controls_per_positive <= 0:
        raise ValueError("controls_per_positive must be positive")
    required = {"chain", "contract_address", "deterministic_rank_sha256"}
    ordered_cases = sorted(str(case) for case in eligible_by_case)
    candidates: dict[str, list[tuple[str, str]]] = {}
    for case in ordered_cases:
        frame = eligible_by_case[case]
        if frame.empty:
            candidates[case] = []
            continue
        missing = sorted(required - set(frame.columns))
        if missing:
            raise ValueError(f"eligible controls missing columns for {case}: {missing}")
        ordered = frame.copy()
        ordered["_chain"] = ordered["chain"].astype(str).str.strip().str.lower()
        ordered["_address"] = (
            ordered["contract_address"].astype(str).str.strip().str.lower()
        )
        ordered = ordered.sort_values(
            ["deterministic_rank_sha256", "_chain", "_address"], kind="stable"
        ).drop_duplicates(["_chain", "_address"])
        candidates[case] = list(zip(ordered["_chain"], ordered["_address"]))

    source = ("source", "")
    sink = ("sink", "")
    adjacency: dict[tuple[str, str], list[list[object]]] = {}

    def add_edge(
        start: tuple[str, str], end: tuple[str, str], capacity: int
    ) -> list[object]:
        adjacency.setdefault(start, [])
        adjacency.setdefault(end, [])
        forward: list[object] = [end, len(adjacency[end]), capacity]
        reverse: list[object] = [start, len(adjacency[start]), 0]
        adjacency[start].append(forward)
        adjacency[end].append(reverse)
        return forward

    case_edges: dict[str, list[tuple[tuple[str, str], list[object]]]] = {
        case: [] for case in ordered_cases
    }
    for case in ordered_cases:
        add_edge(source, ("case", case), controls_per_positive)
    control_identities = sorted(
        {identity for identities in candidates.values() for identity in identities}
    )
    for chain, address in control_identities:
        add_edge(("control", f"{chain}:{address}"), sink, 1)
    for case in ordered_cases:
        for chain, address in candidates[case]:
            edge = add_edge(
                ("case", case), ("control", f"{chain}:{address}"), 1
            )
            case_edges[case].append(((chain, address), edge))

    while True:
        level = {source: 0}
        queue: deque[tuple[str, str]] = deque([source])
        while queue:
            node = queue.popleft()
            for target, _, capacity in adjacency.get(node, []):
                if int(capacity) > 0 and target not in level:
                    level[target] = level[node] + 1
                    queue.append(target)
        if sink not in level:
            break
        cursor = {node: 0 for node in adjacency}

        def send(node: tuple[str, str], amount: int) -> int:
            if node == sink:
                return amount
            edges = adjacency[node]
            while cursor[node] < len(edges):
                edge = edges[cursor[node]]
                target = edge[0]
                if int(edge[2]) > 0 and level.get(target) == level[node] + 1:
                    pushed = send(target, min(amount, int(edge[2])))
                    if pushed:
                        edge[2] = int(edge[2]) - pushed
                        reverse = adjacency[target][int(edge[1])]
                        reverse[2] = int(reverse[2]) + pushed
                        return pushed
                cursor[node] += 1
            return 0

        while send(source, 10**9):
            pass

    return {
        case: [identity for identity, edge in case_edges[case] if int(edge[2]) == 0]
        for case in ordered_cases
    }


def deterministic_matched_controls(
    positives: pd.DataFrame,
    deployments: pd.DataFrame,
    policy: MatchPolicy = MatchPolicy(),
    excluded_addresses: Iterable[str] = (),
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Select cutoff-safe matched deployment controls deterministically.

    Positive records must include an outcome-independent ``prediction_cutoff_time``.
    A control can only enter the risk set if it was deployed no later than that
    cutoff. Matching then uses only variables that are observable at or before the
    cutoff: chain, deployment-time caliper, code size, proxy status and source
    availability stratum. No later activity, exploit outcome or post-cutoff source
    publication is used in selection.
    """
    required_p = {
        "case_name", "chain", "deployment_time", "prediction_cutoff_time",
        "code_size", "proxy_status", "source_verified_at_cutoff",
    }
    required_d = {
        "chain", "contract_address", "deployment_time", "code_size",
        "proxy_status", "source_verified_at_cutoff",
    }
    missing_p = sorted(required_p - set(positives.columns))
    missing_d = sorted(required_d - set(deployments.columns))
    if missing_p or missing_d:
        raise ValueError(f"missing columns positives={missing_p} deployments={missing_d}")

    d = deployments.copy()
    d["contract_address"] = d.contract_address.astype(str).str.lower()
    excluded = {str(x).lower() for x in excluded_addresses}
    d = d[~d.contract_address.isin(excluded)].copy()
    d["_deployment_time"] = _time_series(d, "deployment_time")
    d["_code_size"] = pd.to_numeric(d.code_size, errors="coerce")

    matches: list[dict] = []
    audit: list[dict] = []
    window = pd.Timedelta(days=policy.deployment_window_days)

    for _, p in positives.iterrows():
        pt = pd.to_datetime(p.deployment_time, utc=True, errors="coerce")
        cutoff = pd.to_datetime(p.prediction_cutoff_time, utc=True, errors="coerce")
        if pd.isna(pt) or pd.isna(cutoff):
            raise ValueError(f"invalid deployment/cutoff time for case {p.case_name}")
        if cutoff < pt:
            raise ValueError(f"prediction cutoff precedes deployment for case {p.case_name}")

        psz = pd.to_numeric(pd.Series([p.code_size]), errors="coerce").iloc[0]
        c = d.copy()
        if policy.require_same_chain:
            c = c[c.chain.astype(str) == str(p.chain)]

        # Risk-set gate: never select a contract that did not yet exist at the
        # positive's frozen prediction cutoff.
        if policy.require_control_deployed_by_cutoff:
            c = c[c._deployment_time.notna() & (c._deployment_time <= cutoff)]
        else:
            c = c[c._deployment_time.notna()]

        c = c[c._deployment_time.sub(pt).abs() <= window]
        if pd.notna(psz) and float(psz) > 0:
            c = c[c._code_size.between(float(psz) * policy.code_size_ratio_low, float(psz) * policy.code_size_ratio_high)]
        if policy.require_proxy_status:
            c = c[c.proxy_status.astype(str) == str(p.proxy_status)]
        if policy.require_source_verified_status:
            c = c[c.source_verified_at_cutoff.astype(str) == str(p.source_verified_at_cutoff)]

        eligible_before_dedup = len(c)
        c = c.drop_duplicates("contract_address")
        seed = str(p.case_name)
        c["_rank"] = c.contract_address.map(lambda x: _stable_rank(seed, x))
        c = c.sort_values(["_rank", "contract_address"]).head(policy.controls_per_positive)

        for rank, (_, r) in enumerate(c.iterrows(), start=1):
            matches.append({
                "case_name": p.case_name,
                "match_set_id": hashlib.sha256(str(p.case_name).encode()).hexdigest()[:20],
                "control_rank": rank,
                "chain": r.chain,
                "contract_address": r.contract_address,
                "deployment_time": r.deployment_time,
                "positive_prediction_cutoff_time": cutoff.isoformat(),
                "deployed_by_positive_cutoff": bool(r._deployment_time <= cutoff),
                "code_size": r.code_size,
                "proxy_status": r.proxy_status,
                "source_verified_at_cutoff": r.source_verified_at_cutoff,
                "deterministic_rank_sha256": r._rank,
            })

        audit.append({
            "case_name": p.case_name,
            "prediction_cutoff_time": cutoff.isoformat(),
            "eligible_candidates_before_dedup": int(eligible_before_dedup),
            "eligible_candidates": int(len(c)),
            "controls_selected": int(len(c)),
            "required": policy.controls_per_positive,
            "all_controls_pre_cutoff": bool(len(c) == 0 or (c._deployment_time <= cutoff).all()),
            "complete": bool(len(c) >= policy.controls_per_positive),
        })

    return pd.DataFrame(matches), pd.DataFrame(audit)
