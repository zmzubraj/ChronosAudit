from pathlib import Path
import pandas as pd
from chronosaudit_stage2.control_matching import deterministic_matched_controls, MatchPolicy
from chronosaudit_stage2.deployment_stream import creations_from_geth_calltracer
from chronosaudit_stage2.review_workflow import adjudicate_reviews, create_blinded_reviewer_packets
from chronosaudit_stage2.statistics import wilson_interval, precision_sample_size


def test_control_matching_rejects_post_cutoff_deployments():
    p=pd.DataFrame([{'case_name':'p','chain':'ethereum','deployment_time':'2024-01-01T00:00:00Z','prediction_cutoff_time':'2024-01-10T00:00:00Z','code_size':1000,'proxy_status':'none','source_verified_at_cutoff':True}])
    d=pd.DataFrame([
        {'chain':'ethereum','contract_address':'0x'+'01'*20,'deployment_time':'2024-01-05T00:00:00Z','code_size':1000,'proxy_status':'none','source_verified_at_cutoff':True},
        {'chain':'ethereum','contract_address':'0x'+'02'*20,'deployment_time':'2024-01-11T00:00:00Z','code_size':1000,'proxy_status':'none','source_verified_at_cutoff':True},
    ])
    m,a=deterministic_matched_controls(p,d,MatchPolicy(controls_per_positive=1))
    assert len(m)==1 and m.iloc[0].contract_address.endswith('01'*20)
    assert bool(m.iloc[0].deployed_by_positive_cutoff)
    assert bool(a.iloc[0].all_controls_pre_cutoff)


def test_blinded_packets_hide_machine_candidates(tmp_path):
    src=pd.DataFrame([{'case_name':'c1','incident_name':'x','mechanism_candidate':'reentrancy','protocol_candidate':'foo','incident_reference':'ref'}])
    s=tmp_path/'src.csv'; a=tmp_path/'a.csv'; b=tmp_path/'b.csv'; src.to_csv(s,index=False)
    r=create_blinded_reviewer_packets(s,a,b)
    out=pd.read_csv(a)
    assert r['status']=='blinded_packets_created'
    assert 'mechanism_candidate' not in out.columns and 'protocol_candidate' not in out.columns


def test_third_adjudicator_completes_disagreement(tmp_path):
    cols=['case_name','protocol_family','primary_root_cause','confidence','evidence_references']
    a=pd.DataFrame([['c1','dex','oracle','high','r1']],columns=cols); b=pd.DataFrame([['c1','lending','logic','high','r2']],columns=cols)
    pa=tmp_path/'a.csv'; pb=tmp_path/'b.csv'; po=tmp_path/'out.csv'; pj=tmp_path/'j.csv'; a.to_csv(pa,index=False); b.to_csv(pb,index=False)
    j=pd.DataFrame([{'case_name':'c1','final_protocol_family':'dex','final_primary_root_cause':'oracle','adjudication_rationale':'evidence','evidence_references':'r3'}]); j.to_csv(pj,index=False)
    result=adjudicate_reviews(pa,pb,po,pj)
    assert result['status']=='adjudication_complete' and result['pending_adjudication']==0
    out=pd.read_csv(po); assert out.iloc[0].adjudication_status=='third_adjudicator_complete'


def test_geth_calltracer_create2_adapter():
    rows=[{'txHash':'0xabc','result':{'type':'CALL','calls':[{'type':'CREATE2','from':'0x'+'11'*20,'to':'0x'+'22'*20}]}}]
    out=creations_from_geth_calltracer('ethereum',10,'0x'+'aa'*32,rows)
    assert len(out)==1 and out[0].creation_type=='internal_create2'


def test_statistical_helpers():
    lo,hi=wilson_interval(80,100)
    assert 0.70 < lo < .80 < hi < .90
    assert precision_sample_size(.5,.05) >= 380
