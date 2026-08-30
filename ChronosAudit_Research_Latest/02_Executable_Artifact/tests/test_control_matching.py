import pandas as pd
from chronosaudit_stage2.control_matching import deterministic_matched_controls, MatchPolicy
from chronosaudit_stage2.mechanism_taxonomy import candidate_from_public_label


def test_mechanism_candidates_are_auditable():
    assert candidate_from_public_label("Access Control & Price Oracle Manipulation").family == "authorization_failure"
    assert candidate_from_public_label("Reentrancy").family == "reentrancy"
    assert candidate_from_public_label("").family == "unassigned"


def test_control_matching_is_deterministic_and_pre_cutoff_only():
    positives = pd.DataFrame([{
        "case_name": "p1", "chain": "ethereum", "deployment_time": "2024-01-15T00:00:00Z",
        "prediction_cutoff_time": "2024-02-15T00:00:00Z", "code_size": 1000, "proxy_status": "none", "source_verified_at_cutoff": True,
    }])
    deployments = pd.DataFrame([{
        "chain": "ethereum", "contract_address": f"0x{i:040x}", "deployment_time": "2024-01-16T00:00:00Z",
        "code_size": 900+i, "proxy_status": "none", "source_verified_at_cutoff": True,
    } for i in range(1, 20)])
    a, audit_a = deterministic_matched_controls(positives, deployments, MatchPolicy(controls_per_positive=10))
    b, audit_b = deterministic_matched_controls(positives, deployments, MatchPolicy(controls_per_positive=10))
    assert len(a) == 10
    assert a.contract_address.tolist() == b.contract_address.tolist()
    assert bool(audit_a.iloc[0].complete)
    assert audit_a.to_dict("records") == audit_b.to_dict("records")
