from __future__ import annotations
import hashlib
import math
import random
from collections import defaultdict
import pandas as pd


def identity_key(df: pd.DataFrame) -> pd.Series:
    chain = df['chain'].astype(str).str.lower().replace({'mainnet':'ethereum'})
    addr = df['target_contract_address'].astype(str).str.lower()
    return chain + ':' + addr


def crossing_groups(keys: pd.Series, folds: list[int]) -> int:
    seen=defaultdict(set)
    for k,f in zip(keys.tolist(),folds): seen[k].add(int(f))
    return sum(len(v)>1 for v in seen.values())


def independent_random_folds(n:int,k:int,rng:random.Random): return [rng.randrange(k) for _ in range(n)]

def balanced_random_folds(n:int,k:int,rng:random.Random):
    idx=list(range(n)); rng.shuffle(idx); folds=[0]*n
    for rank,i in enumerate(idx): folds[i]=rank%k
    return folds

def stratified_balanced_folds(strata:pd.Series,k:int,rng:random.Random):
    folds=[0]*len(strata)
    for _,idxs in strata.groupby(strata).groups.items():
        idxs=list(idxs); rng.shuffle(idxs)
        for rank,i in enumerate(idxs): folds[i]=rank%k
    return folds

def deterministic_identity_group_folds(keys:pd.Series,k:int):
    mapping={}
    for key in sorted(set(keys)):
        mapping[key]=int(hashlib.sha256(key.encode()).hexdigest(),16)%k
    return [mapping[k_] for k_ in keys]

def audit_split_strategies(df:pd.DataFrame,k:int=5,simulations:int=1000,seed:int=20260807):
    keys=identity_key(df); dup_sizes=keys.value_counts(); repeated=dup_sizes[dup_sizes>1]
    out={'rows':len(df),'unique_identities':int(keys.nunique()),'repeated_identity_groups':int(len(repeated)),'repeated_group_sizes':[int(x) for x in repeated.tolist()],'k':k,'simulations':simulations}
    for name,fn in [('independent_random',lambda r: independent_random_folds(len(df),k,r)),('balanced_shuffled_kfold',lambda r: balanced_random_folds(len(df),k,r)),('chain_stratified_balanced_kfold',lambda r: stratified_balanced_folds(df['chain'].astype(str),k,r))]:
        vals=[]
        for s in range(simulations):
            rng=random.Random(seed+s); vals.append(crossing_groups(keys,fn(rng)))
        out[name]={'leaky_splits':sum(v>0 for v in vals),'leaky_fraction':sum(v>0 for v in vals)/simulations,'mean_crossing_identity_groups':sum(vals)/simulations,'min_crossing':min(vals),'max_crossing':max(vals)}
    grouped=deterministic_identity_group_folds(keys,k)
    out['identity_group_kfold']={'crossing_identity_groups':crossing_groups(keys,grouped),'leaky':crossing_groups(keys,grouped)>0}
    # Closed form applies because every repeated identity in the current seed is a pair.
    if len(repeated) and set(repeated.tolist())=={2}:
        m=len(repeated); out['pair_only_theory']={'expected_crossing_groups_independent_random':m*(1-1/k),'probability_at_least_one_crossing_independent_random':1-(1/k)**m}
    return out


def _group_fold(values: pd.Series, k:int, salt:str) -> list[int]:
    mapping={}
    for v in sorted(set(values.astype(str))):
        mapping[v]=int(hashlib.sha256((salt+"|"+v).encode()).hexdigest(),16)%k
    return [mapping[str(v)] for v in values]


def r0_r5_partition_certification(df: pd.DataFrame, k:int=5) -> dict:
    """Certify whether the data contain sufficient keys to construct R0--R5.

    This is an evidence certification layer, not a detector-performance result.
    It prevents the manuscript from reporting an R-level as executed when the
    required lineage/family key is missing or preliminary/non-adjudicated.
    """
    req={
        'R0': [],
        'R1': ['chain','target_contract_address'],
        'R2': ['prediction_cutoff_time'],
        'R3': ['protocol_family'],
        'R4': ['implementation_family'],
        'R5': ['mechanism_family'],
    }
    out={'rows':len(df),'levels':{}}
    for level,cols in req.items():
        missing=[c for c in cols if c not in df.columns]
        nulls={c:int(df[c].isna().sum() + (df[c].astype(str).str.strip().isin(['','nan','None']).sum() if c in df else 0)) for c in cols if c in df}
        complete=(not missing) and all(v==0 for v in nulls.values())
        out['levels'][level]={'required_columns':cols,'missing_columns':missing,'null_or_blank_counts':nulls,'evidence_complete':complete}
    # R1 crossing is directly measurable when identities exist.
    if out['levels']['R1']['evidence_complete']:
        keys=identity_key(df); folds=deterministic_identity_group_folds(keys,k)
        out['levels']['R1']['crossing_identity_groups']=crossing_groups(keys,folds)
    for level,col in [('R3','protocol_family'),('R4','implementation_family'),('R5','mechanism_family')]:
        if out['levels'][level]['evidence_complete']:
            folds=_group_fold(df[col].astype(str),k,level)
            out['levels'][level]['groups']=int(df[col].astype(str).nunique())
            out['levels'][level]['group_crossings']=crossing_groups(df[col].astype(str),folds)
    out['highest_certified_level']=max((x for x in req if out['levels'][x]['evidence_complete']), key=lambda x:int(x[1]), default='R0')
    return out


def leave_one_mechanism_family_out(df:pd.DataFrame, mechanism_col:str='mechanism_family') -> list[dict]:
    if mechanism_col not in df: raise ValueError('missing mechanism family')
    vals=df[mechanism_col].astype(str).str.strip()
    if vals.isin(['','nan','None']).any(): raise ValueError('mechanism family incomplete')
    out=[]
    for fam in sorted(vals.unique()):
        test=(vals==fam)
        out.append({'held_out_mechanism_family':fam,'train_rows':int((~test).sum()),'test_rows':int(test.sum()),'train_mechanism_families':int(vals[~test].nunique()),'test_mechanism_families':1})
    return out


def provisional_r0_r5_execution(df: pd.DataFrame, k: int = 5) -> dict:
    """Execute the strongest reproducible R0--R5 *provisional* partitions available.

    This deliberately separates partition execution from scientific certification.
    R2 uses incident chronology (retrospective temporal split), R3/R5 may use
    candidate labels, and R4 falls back to exact identity when historical runtime
    implementation hashes are unavailable. These results are useful for detecting
    obvious contamination but MUST NOT be reported as strict ChronosAudit R2--R5.
    """
    out = {"rows": len(df), "levels": {}, "certification": "PROVISIONAL_NOT_STRICT"}
    keys = identity_key(df)
    # R0: balanced row-level split.
    rng = random.Random(20260807)
    r0 = balanced_random_folds(len(df), k, rng)
    out["levels"]["R0"] = {"executed": True, "crossing_identity_groups": crossing_groups(keys, r0), "basis": "balanced row-level K-fold"}
    # R1: exact identity grouping.
    r1 = deterministic_identity_group_folds(keys, k)
    out["levels"]["R1"] = {"executed": True, "crossing_identity_groups": crossing_groups(keys, r1), "basis": "chain+address identity groups"}
    # R2 provisional: chronological split by incident date, not prediction cutoff.
    if "incident_date" in df and pd.to_datetime(df["incident_date"], errors="coerce").notna().all():
        order = pd.to_datetime(df["incident_date"]).sort_values().index.tolist()
        folds = [None] * len(df)
        for rank, idx in enumerate(order): folds[idx] = min(k - 1, int(rank * k / max(1, len(order))))
        out["levels"]["R2"] = {"executed": True, "crossing_identity_groups": crossing_groups(keys, folds),
            "basis": "incident-date chronological folds", "strict_certified": False,
            "warning": "incident chronology is outcome-known and cannot substitute for deployment+landmark prediction cutoff"}
    else:
        out["levels"]["R2"] = {"executed": False, "reason": "incident_date incomplete"}
    # R3 candidate protocol groups.
    pc = next((c for c in ("protocol_family", "protocol_candidate", "case_name") if c in df.columns), None)
    if pc:
        vals = df[pc].astype(str).fillna("unassigned")
        folds = _group_fold(vals, k, "R3-provisional")
        out["levels"]["R3"] = {"executed": True, "groups": int(vals.nunique()), "group_crossings": crossing_groups(vals, folds),
            "basis": pc, "strict_certified": pc == "protocol_family",
            "warning": None if pc == "protocol_family" else "candidate/entity labels are not independent reviewer-final protocol families"}
    # R4 lower bound: implementation family if available else exact identity.
    if "implementation_family" in df.columns and df["implementation_family"].astype(str).str.strip().replace("nan", "").ne("").all():
        vals = df["implementation_family"].astype(str); basis = "implementation_family"; strict = True
    else:
        vals = keys; basis = "exact_identity_lower_bound"; strict = False
    folds = _group_fold(vals, k, "R4-provisional")
    out["levels"]["R4"] = {"executed": True, "groups": int(vals.nunique()), "group_crossings": crossing_groups(vals, folds),
        "basis": basis, "strict_certified": strict,
        "warning": None if strict else "exact identity under-approximates shared implementation/proxy families"}
    # R5 candidate mechanism grouping.
    mc = next((c for c in ("mechanism_family", "mechanism_candidate") if c in df.columns), None)
    if mc:
        vals = df[mc].astype(str).fillna("unassigned")
        folds = _group_fold(vals, k, "R5-provisional")
        lomo = []
        for fam in sorted(vals.unique()):
            test = vals == fam
            lomo.append({"held_out": fam, "train_rows": int((~test).sum()), "test_rows": int(test.sum())})
        out["levels"]["R5"] = {"executed": True, "groups": int(vals.nunique()), "group_crossings": crossing_groups(vals, folds),
            "basis": mc, "strict_certified": mc == "mechanism_family", "lomo": lomo,
            "warning": None if mc == "mechanism_family" else "public-label candidates are not independent adjudicated mechanism families"}
    else:
        out["levels"]["R5"] = {"executed": False, "reason": "no mechanism label/candidate"}
    return out
