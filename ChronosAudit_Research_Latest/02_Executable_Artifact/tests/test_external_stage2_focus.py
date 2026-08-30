from pathlib import Path
import pandas as pd

from chronosaudit_stage2.external_evidence import default_external_sources, gate_assessment, write_registry
from chronosaudit_stage2.review_workflow import _krippendorff_alpha_nominal, review_reliability_summary
from chronosaudit_stage2.source_history import ingest_sourcify_export, source_at_cutoff_assessment, SourceObservation
from chronosaudit_stage2.statistics import kaplan_meier_censoring_survival, landmark_outcomes, ipcw_binary_metric, censoring_sensitivity_bounds
from chronosaudit_stage2.split_audit import r0_r5_partition_certification, leave_one_mechanism_family_out


def test_external_registry(tmp_path):
    src=default_external_sources(); assert any(x.record_count and x.record_count >= 20000 for x in src)
    r=write_registry(tmp_path/'registry.csv',src); assert r['rows'] >= 5
    assert all(x['can_generate'] is False for x in gate_assessment())


def test_kripp_alpha():
    assert _krippendorff_alpha_nominal(['a','b'],['a','b']) == 1.0
    assert _krippendorff_alpha_nominal([],[]) is None


def test_review_summary(tmp_path):
    cols=['case_name','protocol_family','primary_root_cause','confidence','evidence_references']
    a=pd.DataFrame([['x','p','m','high','r'],['y','q','n','med','s']],columns=cols)
    b=a.copy(); a.to_csv(tmp_path/'a.csv',index=False); b.to_csv(tmp_path/'b.csv',index=False)
    s=review_reliability_summary(tmp_path/'a.csv',tmp_path/'b.csv'); assert s['protocol_krippendorff_alpha_nominal']==1.0


def test_sourcify_bulk_and_assessment(tmp_path):
    pd.DataFrame([{'address':'0xabc','chain_id':1,'verified_at':'2024-01-01T00:00:00+00:00','match_type':'exact_match'}]).to_csv(tmp_path/'s.csv',index=False)
    obs=ingest_sourcify_export(tmp_path/'s.csv'); assert len(obs)==1
    a=source_at_cutoff_assessment(obs,'2024-01-02T00:00:00+00:00'); assert a['source_admissible'] is True
    late=source_at_cutoff_assessment(obs,'2023-12-31T00:00:00+00:00'); assert late['source_admissible'] is False and late['absence_proven'] is False


def test_censor_functions():
    g=kaplan_meier_censoring_survival([10,20,30],[1,0,1]); assert len(g)==3 and (g>0).all()
    df=pd.DataFrame({'followup_days':[10,40,100],'event_observed':[1,0,0]})
    rows=landmark_outcomes(df,horizons=(30,90)); assert rows[0]['events_by_horizon']==1
    m=ipcw_binary_metric([1,0,0],[.9,.8,.1],[10,40,100],[1,0,0],30,.5); assert m['evaluable']>=2
    lo,hi=censoring_sensitivity_bounds(1,1,8); assert lo==.1 and hi==.2


def test_r0_r5_certification():
    df=pd.DataFrame({
        'chain':['ethereum']*6,
        'target_contract_address':[f'0x{i}' for i in range(6)],
        'prediction_cutoff_time':['2026-01-01']*6,
        'protocol_family':['p','p','q','q','r','r'],
        'implementation_family':['i1','i1','i2','i2','i3','i3'],
        'mechanism_family':['m1','m1','m2','m2','m3','m3'],
    })
    c=r0_r5_partition_certification(df,k=3); assert c['highest_certified_level']=='R5'
    loo=leave_one_mechanism_family_out(df); assert len(loo)==3

from chronosaudit_stage2.review_workflow import adjudicate_reviews, external_corroboration_table, create_blinded_reviewer_packets


def test_full_adjudication_and_external_corroboration(tmp_path):
    raw=pd.DataFrame([
        {'case_name':'x','incident_name':'X','chain':'ethereum','target_contract_address':'0x1','incident_date':'2024-01-01','incident_reference':'r'},
        {'case_name':'y','incident_name':'Y','chain':'ethereum','target_contract_address':'0x2','incident_date':'2024-01-02','incident_reference':'s'},
    ])
    raw.to_csv(tmp_path/'raw.csv',index=False)
    p=create_blinded_reviewer_packets(tmp_path/'raw.csv',tmp_path/'pa.csv',tmp_path/'pb.csv'); assert p['cases']==2
    cols=['case_name','protocol_family','primary_root_cause','confidence','evidence_references']
    a=pd.DataFrame([['x','p','m','high','r'],['y','q','n','high','s']],columns=cols)
    b=pd.DataFrame([['x','p','m','high','r'],['y','q2','n2','medium','s2']],columns=cols)
    a.to_csv(tmp_path/'a.csv',index=False); b.to_csv(tmp_path/'b.csv',index=False)
    adj=pd.DataFrame([{'case_name':'y','final_protocol_family':'q','final_primary_root_cause':'n','adjudication_rationale':'evidence wins','evidence_references':'third'}])
    adj.to_csv(tmp_path/'adj.csv',index=False)
    res=adjudicate_reviews(tmp_path/'a.csv',tmp_path/'b.csv',tmp_path/'final.csv',tmp_path/'adj.csv'); assert res['status']=='adjudication_complete' and res['pending_adjudication']==0
    ext=pd.DataFrame([
      {'case_name':'x','external_protocol_family':'p','external_primary_root_cause':'m','external_evidence_references':'paper'},
      {'case_name':'y','external_protocol_family':'q','external_primary_root_cause':'n','external_evidence_references':'paper2'},
    ])
    ext.to_csv(tmp_path/'ext.csv',index=False)
    cor=external_corroboration_table(tmp_path/'final.csv',tmp_path/'ext.csv',tmp_path/'cor.csv','external'); assert cor['matched_cases']==2 and cor['mechanism_agreement']==1.0
