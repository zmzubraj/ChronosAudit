import pandas as pd
from chronosaudit_stage2.split_audit import audit_split_strategies

def test_grouped_split_has_zero_identity_leakage():
    df=pd.DataFrame({'chain':['ethereum']*4,'target_contract_address':['0x1','0x1','0x2','0x3']})
    r=audit_split_strategies(df,k=2,simulations=50)
    assert r['identity_group_kfold']['crossing_identity_groups']==0
    assert r['repeated_identity_groups']==1
