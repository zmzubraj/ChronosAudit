from pathlib import Path
import pandas as pd

from chronosaudit_stage2.evidence_sources import enrich_scone_incidents
from chronosaudit_stage2.source_history import availability_admissible


def test_frozen_incident_index_covers_full_scone(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = enrich_scone_incidents(
        root / 'raw' / 'scone_bench.csv',
        root / 'raw' / 'external' / 'defihacklabs',
        tmp_path / 'incidents.csv',
        tmp_path / 'prov.csv',
        tmp_path / 'matching.csv',
    )
    assert result['scone_rows'] == 417
    assert result['matched_rows'] == 417
    assert result['coverage'] == 1.0
    out = pd.read_csv(tmp_path / 'incidents.csv')
    assert out.incident_record_sha256.notna().all()
    assert out.source_snapshot_sha256.notna().all()


def test_enrichment_reproduces_original_50_dates(tmp_path):
    root = Path(__file__).resolve().parents[1]
    enrich_scone_incidents(
        root / 'raw' / 'scone_bench.csv', root / 'raw' / 'external' / 'defihacklabs',
        tmp_path / 'incidents.csv', tmp_path / 'prov.csv', tmp_path / 'matching.csv'
    )
    original = pd.read_csv(root / 'raw' / 'incident_explorer_seed.csv')[['case_name','incident_date']]
    enriched = pd.read_csv(tmp_path / 'incidents.csv')[['case_name','incident_date']]
    merged = original.merge(enriched, on='case_name', suffixes=('_old','_new'))
    assert len(merged) == 50
    assert (merged.incident_date_old == merged.incident_date_new).all()


def test_source_availability_is_asymmetric_and_cutoff_safe():
    assert availability_admissible('2024-01-01T00:00:00Z', '2024-02-01T00:00:00Z') is True
    assert availability_admissible('2024-03-01T00:00:00Z', '2024-02-01T00:00:00Z') is False
    assert availability_admissible(None, '2024-02-01T00:00:00Z') is None


def test_etherscan_creation_adapter_is_exposed():
    from chronosaudit_stage2.source_history import DeploymentObservation, etherscan_deployment_observation
    assert DeploymentObservation.__annotations__["creation_tx_hash"] is not None
    assert callable(etherscan_deployment_observation)
