from __future__ import annotations

import hashlib
import json
from collections import deque
from collections.abc import Iterable

import pandas as pd


class ControlPairScopeError(ValueError):
    """Raised when a cutoff-safe control evidence-acquisition scope cannot be built."""


_POSITIVE_REQUIRED = {
    "case_name",
    "chain",
    "target_contract_address",
    "deployment_time",
    "prediction_cutoff_time",
    "positive_record_sha256",
}

_DENOMINATOR_REQUIRED = {
    "deployment_id",
    "chain",
    "contract_address",
    "deployment_time",
    "source_record_sha256",
    "source_manifest_sha256",
    "row_evidence_sha256",
    "authority_projection_sha256",
    "counter_authority",
}

_OUTPUT_COLUMNS = (
    "case_name",
    "chain",
    "positive_address",
    "positive_deployment_time",
    "positive_prediction_cutoff_time",
    "positive_record_sha256",
    "deployment_id",
    "control_address",
    "control_deployment_time",
    "deployment_distance_seconds",
    "denominator_record_sha256",
    "source_manifest_sha256",
    "row_evidence_sha256",
    "authority_projection_sha256",
    "required_covariate_cutoff_time",
    "scope_status",
    "selection_authorized",
    "pair_scope_record_sha256",
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _normalize_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _timestamp(value: object, label: str) -> pd.Timestamp:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        raise ControlPairScopeError(f"{label}_invalid")
    return parsed


def _utc_iso(value: pd.Timestamp) -> str:
    return value.isoformat().replace("+00:00", "Z")


def maximum_no_reuse_allocation(
    scope: pd.DataFrame,
    *,
    controls_per_positive: int = 10,
    case_names: Iterable[str] | None = None,
) -> dict[str, object]:
    """Compute a deterministic maximum-cardinality pair allocation.

    This is a feasibility calculation only. It does not select qualified
    controls or use any matching covariate beyond the already frozen scope.
    """
    required = {"case_name", "chain", "control_address"}
    missing = sorted(required - set(scope.columns))
    if missing:
        raise ControlPairScopeError(
            f"allocation_scope_missing_columns:{','.join(missing)}"
        )
    if controls_per_positive <= 0:
        raise ControlPairScopeError("controls_per_positive_invalid")

    cases = {str(value) for value in (case_names or [])}
    cases.update(scope["case_name"].astype(str).tolist())
    ordered_cases = sorted(cases)
    pairs = sorted(
        {
            (
                str(row["case_name"]),
                f"{str(row['chain']).strip().lower()}:{str(row['control_address']).strip().lower()}",
            )
            for row in scope.to_dict("records")
        }
    )

    source = ("source", "")
    sink = ("sink", "")
    adjacency: dict[tuple[str, str], list[list[object]]] = {}

    def add_edge(
        start: tuple[str, str], end: tuple[str, str], capacity: int
    ) -> list[object]:
        adjacency.setdefault(start, [])
        adjacency.setdefault(end, [])
        forward: list[object] = [end, len(adjacency[end]), capacity, capacity]
        reverse: list[object] = [start, len(adjacency[start]), 0, 0]
        adjacency[start].append(forward)
        adjacency[end].append(reverse)
        return forward

    case_edges: dict[str, list[list[object]]] = {case: [] for case in ordered_cases}
    controls = sorted({control for _, control in pairs})
    for case in ordered_cases:
        add_edge(source, ("case", case), controls_per_positive)
    for control in controls:
        add_edge(("control", control), sink, 1)
    for case, control in pairs:
        edge = add_edge(("case", case), ("control", control), 1)
        case_edges[case].append(edge)

    flow = 0
    while True:
        level = {source: 0}
        queue: deque[tuple[str, str]] = deque([source])
        while queue:
            node = queue.popleft()
            for edge in adjacency.get(node, []):
                target = edge[0]
                capacity = int(edge[2])
                if capacity > 0 and target not in level:
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

        while True:
            pushed = send(source, 10**9)
            if not pushed:
                break
            flow += pushed

    per_case_allocated = {
        case: sum(int(edge[2]) == 0 for edge in case_edges[case])
        for case in ordered_cases
    }
    reachable = {source}
    queue = deque([source])
    while queue:
        node = queue.popleft()
        for edge in adjacency.get(node, []):
            target = edge[0]
            if int(edge[2]) > 0 and target not in reachable:
                reachable.add(target)
                queue.append(target)
    minimum_cut_capacity = sum(
        int(edge[3])
        for node in reachable
        for edge in adjacency.get(node, [])
        if edge[0] not in reachable and int(edge[3]) > 0
    )
    if minimum_cut_capacity != flow:
        raise ControlPairScopeError("maximum_allocation_min_cut_mismatch")
    target = len(ordered_cases) * controls_per_positive
    return {
        "schema_version": "chronosaudit.control_pair_maximum_allocation.v1",
        "controls_per_positive": int(controls_per_positive),
        "case_count": int(len(ordered_cases)),
        "unique_control_identities": int(len(controls)),
        "maximum_assignable_controls": int(flow),
        "minimum_cut_capacity": int(minimum_cut_capacity),
        "max_flow_min_cut_verified": True,
        "target_control_rows": int(target),
        "total_shortfall": int(target - flow),
        "fully_allocated_cases": int(
            sum(value == controls_per_positive for value in per_case_allocated.values())
        ),
        "cases_with_shortfall": int(
            sum(value < controls_per_positive for value in per_case_allocated.values())
        ),
        "per_case_allocated": per_case_allocated,
    }


def build_denominator_expansion_requirements(
    *,
    positives: pd.DataFrame,
    scope: pd.DataFrame,
    deployment_window_days: int = 30,
    controls_per_positive: int = 10,
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Build a case-bound minimum historical-denominator expansion ledger."""
    positive_required = {
        "case_name",
        "chain",
        "deployment_time",
        "prediction_cutoff_time",
        "positive_record_sha256",
    }
    missing = sorted(positive_required - set(positives.columns))
    if missing:
        raise ControlPairScopeError(
            f"expansion_positive_missing_columns:{','.join(missing)}"
        )
    if positives["case_name"].astype(str).duplicated().any():
        raise ControlPairScopeError("positive_duplicate_case_name")
    if deployment_window_days < 0:
        raise ControlPairScopeError("deployment_window_days_invalid")
    case_names = positives["case_name"].astype(str).tolist()
    allocation = maximum_no_reuse_allocation(
        scope,
        controls_per_positive=controls_per_positive,
        case_names=case_names,
    )
    pair_counts = {case: 0 for case in case_names}
    pair_counts.update(
        {
            str(case): int(count)
            for case, count in scope["case_name"].astype(str).value_counts().items()
        }
    )
    window = pd.Timedelta(days=deployment_window_days)
    records: list[dict[str, object]] = []
    for positive in positives.sort_values(["case_name", "chain"], kind="stable").to_dict(
        "records"
    ):
        case_name = str(positive["case_name"])
        deployment = _timestamp(
            positive["deployment_time"], "positive_deployment_time"
        )
        cutoff = _timestamp(
            positive["prediction_cutoff_time"], "positive_prediction_cutoff_time"
        )
        allocated = int(allocation["per_case_allocated"][case_name])
        deficit = max(0, controls_per_positive - allocated)
        record: dict[str, object] = {
            "case_name": case_name,
            "chain": str(positive["chain"]).strip().lower(),
            "positive_deployment_time": _utc_iso(deployment),
            "positive_prediction_cutoff_time": _utc_iso(cutoff),
            "positive_record_sha256": str(positive["positive_record_sha256"]).lower(),
            "admissible_deployment_start": _utc_iso(deployment - window),
            "admissible_deployment_end": _utc_iso(min(deployment + window, cutoff)),
            "existing_pair_count": int(pair_counts[case_name]),
            "maximum_flow_allocated": allocated,
            "controls_required": int(controls_per_positive),
            "minimum_additional_distinct_slots": deficit,
            "require_new_chain_address_identity": True,
            "require_deployed_by_positive_cutoff": True,
            "require_pair_specific_cutoff_covariates": True,
            "expansion_status": (
                "HISTORICAL_DENOMINATOR_EXPANSION_REQUIRED"
                if deficit
                else "NO_DEPLOYMENT_SCOPE_DEFICIT"
            ),
            "selection_authorized": False,
        }
        record["expansion_requirement_sha256"] = _canonical_sha256(record)
        records.append(record)
    output = pd.DataFrame(records)
    minimum_additional = int(
        output["minimum_additional_distinct_slots"].sum()
    )
    if minimum_additional != int(allocation["total_shortfall"]):
        raise ControlPairScopeError("expansion_shortfall_allocation_mismatch")
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_denominator_expansion_requirements.v1",
        "decision": (
            "HISTORICAL_DENOMINATOR_EXPANSION_REQUIRED"
            if minimum_additional
            else "DEPLOYMENT_SCOPE_COMPLETE"
        ),
        "selection_authorized": False,
        "sufficiency": "NECESSARY_NOT_SUFFICIENT_BEFORE_COVARIATE_FILTERS",
        "deployment_window_days": int(deployment_window_days),
        "controls_per_positive": int(controls_per_positive),
        "case_count": int(len(output)),
        "minimum_additional_distinct_slots": minimum_additional,
        "cases_requiring_expansion": int(
            output["minimum_additional_distinct_slots"].gt(0).sum()
        ),
        "maximum_no_reuse_allocation": allocation,
        "records_sha256": _canonical_sha256(output.to_dict("records")),
        "warning": (
            "The minimum is the exact deficit in the deployment-only graph. "
            "Additional code-size, proxy, source-verification, clone, and protocol "
            "filters can increase the required acquisition volume."
        ),
    }
    return output, manifest


def build_control_pair_acquisition_scope(
    *,
    positives: pd.DataFrame,
    denominator: pd.DataFrame,
    deployment_window_days: int = 30,
    controls_per_positive: int = 10,
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Freeze the deployment-only pairs needing cutoff-indexed covariate evidence.

    This is an evidence-acquisition scope, not a matched-control selection. It
    deliberately ignores code, proxy, source-verification, protocol, activity,
    mechanism, and outcome columns.
    """
    positive_missing = sorted(_POSITIVE_REQUIRED - set(positives.columns))
    denominator_missing = sorted(_DENOMINATOR_REQUIRED - set(denominator.columns))
    if positive_missing:
        raise ControlPairScopeError(
            f"positive_missing_columns:{','.join(positive_missing)}"
        )
    if denominator_missing:
        raise ControlPairScopeError(
            f"denominator_missing_columns:{','.join(denominator_missing)}"
        )
    if positives["case_name"].astype(str).duplicated().any():
        raise ControlPairScopeError("positive_duplicate_case_name")
    if denominator.duplicated(["chain", "contract_address"]).any():
        raise ControlPairScopeError("denominator_duplicate_chain_address")
    if not denominator["counter_authority"].map(_normalize_bool).all():
        raise ControlPairScopeError("denominator_unauthorized_row")
    for field in ("positive_record_sha256",):
        if not positives[field].map(_is_sha256).all():
            raise ControlPairScopeError(f"{field}_invalid")
    for field in (
        "source_record_sha256",
        "source_manifest_sha256",
        "row_evidence_sha256",
        "authority_projection_sha256",
    ):
        if not denominator[field].map(_is_sha256).all():
            raise ControlPairScopeError(f"{field}_invalid")
    if deployment_window_days < 0:
        raise ControlPairScopeError("deployment_window_days_invalid")
    if controls_per_positive <= 0:
        raise ControlPairScopeError("controls_per_positive_invalid")

    positive_identities = {
        (str(row["chain"]).strip().lower(), str(row["target_contract_address"]).strip().lower())
        for row in positives.to_dict("records")
    }
    denominator_base = denominator.loc[:, sorted(_DENOMINATOR_REQUIRED)].copy()
    denominator_base["chain"] = denominator_base["chain"].astype(str).str.strip().str.lower()
    denominator_base["contract_address"] = (
        denominator_base["contract_address"].astype(str).str.strip().str.lower()
    )
    denominator_base["_deployment_timestamp"] = denominator_base["deployment_time"].map(
        lambda value: _timestamp(value, "denominator_deployment_time")
    )
    window = pd.Timedelta(days=deployment_window_days)
    records: list[dict[str, object]] = []

    ordered_positives = positives.sort_values(["case_name", "chain"], kind="stable")
    for positive in ordered_positives.to_dict("records"):
        chain = str(positive["chain"]).strip().lower()
        positive_address = str(positive["target_contract_address"]).strip().lower()
        deployment_time = _timestamp(
            positive["deployment_time"], "positive_deployment_time"
        )
        cutoff_time = _timestamp(
            positive["prediction_cutoff_time"], "positive_prediction_cutoff_time"
        )
        if cutoff_time < deployment_time:
            raise ControlPairScopeError("positive_cutoff_precedes_deployment")

        eligible = denominator_base[
            (denominator_base["chain"] == chain)
            & (denominator_base["_deployment_timestamp"] <= cutoff_time)
            & (
                denominator_base["_deployment_timestamp"].sub(deployment_time).abs()
                <= window
            )
        ].copy()
        if not eligible.empty:
            eligible = eligible[
                ~eligible.apply(
                    lambda row: (str(row["chain"]), str(row["contract_address"]))
                    in positive_identities,
                    axis=1,
                )
            ]
        eligible = eligible.sort_values(
            ["contract_address", "deployment_id"], kind="stable"
        )
        for control in eligible.to_dict("records"):
            control_deployment = control.pop("_deployment_timestamp")
            record: dict[str, object] = {
                "case_name": str(positive["case_name"]),
                "chain": chain,
                "positive_address": positive_address,
                "positive_deployment_time": _utc_iso(deployment_time),
                "positive_prediction_cutoff_time": _utc_iso(cutoff_time),
                "positive_record_sha256": str(positive["positive_record_sha256"]).lower(),
                "deployment_id": str(control["deployment_id"]),
                "control_address": str(control["contract_address"]),
                "control_deployment_time": _utc_iso(control_deployment),
                "deployment_distance_seconds": int(
                    abs((control_deployment - deployment_time).total_seconds())
                ),
                "denominator_record_sha256": str(control["source_record_sha256"]).lower(),
                "source_manifest_sha256": str(control["source_manifest_sha256"]).lower(),
                "row_evidence_sha256": str(control["row_evidence_sha256"]).lower(),
                "authority_projection_sha256": str(
                    control["authority_projection_sha256"]
                ).lower(),
                "required_covariate_cutoff_time": _utc_iso(cutoff_time),
                "scope_status": "PAIR_COVARIATE_EVIDENCE_REQUIRED",
                "selection_authorized": False,
            }
            record["pair_scope_record_sha256"] = _canonical_sha256(record)
            records.append(record)

    output = pd.DataFrame(records, columns=_OUTPUT_COLUMNS)
    if not output.empty:
        output = output.sort_values(
            ["case_name", "control_address", "deployment_id"], kind="stable"
        ).reset_index(drop=True)
    per_case = {str(case): 0 for case in ordered_positives["case_name"].tolist()}
    if not output.empty:
        per_case.update(
            {
                str(case): int(count)
                for case, count in output["case_name"].value_counts().sort_index().items()
            }
        )
    unique_control_identities = int(
        output.loc[:, ["chain", "control_address"]].drop_duplicates().shape[0]
    )
    target_rows = int(len(positives) * controls_per_positive)
    cases_with_zero_pairs = sum(count == 0 for count in per_case.values())
    cases_under_required = sum(
        count < controls_per_positive for count in per_case.values()
    )
    no_reuse_upper_bound = min(int(len(output)), unique_control_identities)
    maximum_allocation = maximum_no_reuse_allocation(
        output,
        controls_per_positive=controls_per_positive,
        case_names=ordered_positives["case_name"].astype(str).tolist(),
    )
    scope_feasible = (
        cases_under_required == 0 and no_reuse_upper_bound >= target_rows
    )
    manifest: dict[str, object] = {
        "schema_version": "chronosaudit.control_pair_acquisition_scope.v1",
        "decision": "PAIR_COVARIATE_EVIDENCE_REQUIRED",
        "selection_authorized": False,
        "acquisition_unit": "positive_control_pair_at_positive_prediction_cutoff",
        "deployment_window_days": int(deployment_window_days),
        "controls_per_positive": int(controls_per_positive),
        "positive_count": int(len(positives)),
        "denominator_count": int(len(denominator)),
        "pair_count": int(len(output)),
        "per_case_pair_counts": per_case,
        "feasibility": {
            "decision": (
                "DEPLOYMENT_RISK_SET_FEASIBLE_FOR_COVARIATE_ACQUISITION"
                if scope_feasible
                else "REDESIGN_REQUIRED_INSUFFICIENT_DEPLOYMENT_RISK_SET"
            ),
            "target_control_rows": target_rows,
            "unique_control_identities": unique_control_identities,
            "no_reuse_control_row_upper_bound": no_reuse_upper_bound,
            "maximum_no_reuse_allocation": maximum_allocation,
            "cases_with_zero_pairs": int(cases_with_zero_pairs),
            "cases_under_required_controls": int(cases_under_required),
            "additional_covariate_filters_applied": False,
        },
        "records_sha256": _canonical_sha256(output.to_dict("records")),
        "excluded_columns": [
            "activity",
            "mechanism_family",
            "outcome",
            "post_cutoff_activity",
            "protocol_family",
            "proxy_status",
            "source_verified_at_cutoff",
        ],
    }
    return output, manifest
