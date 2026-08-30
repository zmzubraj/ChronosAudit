import json
from pathlib import Path
import pandas as pd

from chronosaudit_stage2.review_workflow import reviewer_independence_check
from chronosaudit_stage2.source_history import ingest_sourcify_deployments_export, pinned_export_manifest
from chronosaudit_stage2.split_audit import provisional_r0_r5_execution
from chronosaudit_stage2.external_evidence import default_external_sources


def test_reviewer_independence(tmp_path):
    a=tmp_path/'a.json'; b=tmp_path/'b.json'
    a.write_text(json.dumps({'reviewer_id':'A','organization':'Org1','conflict_statement':'none','completed_at_utc':'2026-08-07T00:00:00Z'}))
    b.write_text(json.dumps({'reviewer_id':'B','organization':'Org2','conflict_statement':'none','completed_at_utc':'2026-08-07T00:00:00Z'}))
    r=reviewer_independence_check(a,b)
    assert r['status']=='independence_metadata_pass'


def test_sourcify_deployment_export_and_manifest(tmp_path):
    p=tmp_path/'deploy.csv'
    pd.DataFrame([{'chain_id':1,'address':'0xABC','block_number':123,'transaction_hash':'0xTX','created_at':'2024-01-01T00:00:00Z'}]).to_csv(p,index=False)
    rows=ingest_sourcify_deployments_export(p)
    assert rows[0]['chain']=='ethereum'
    assert rows[0]['deployment_block']==123
    m=pinned_export_manifest(p,'sourcify','gs://example/export.csv')
    assert len(m['sha256'])==64 and m['bytes']>0


def test_provisional_r0_r5_executes_current_candidate_fields():
    df=pd.DataFrame({
        'chain':['mainnet','mainnet','bsc','bsc'],
        'target_contract_address':['0x1','0x1','0x2','0x3'],
        'incident_date':['2024-01-01','2024-02-01','2024-03-01','2024-04-01'],
        'protocol_candidate':['p1','p1','p2','p3'],
        'mechanism_candidate':['access','access','price','logic'],
    })
    out=provisional_r0_r5_execution(df,k=2)
    assert all(out['levels'][x]['executed'] for x in ['R0','R1','R2','R3','R4','R5'])
    assert out['levels']['R2']['strict_certified'] is False
    assert out['levels']['R5']['strict_certified'] is False


def test_external_sources_include_public_evidence_layers():
    ids={s.source_id for s in default_external_sources()}
    assert {'scone_2025_2026','anthropic_recent_2849','dive_2026','cyberchainbench_2026','reevmbench_2026'} <= ids
