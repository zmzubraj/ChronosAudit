from __future__ import annotations
import math
import numpy as np
import pandas as pd

def wilson_interval(successes:int,n:int,z:float=1.959963984540054):
    if n<=0: return (None,None)
    p=successes/n; den=1+z*z/n; center=(p+z*z/(2*n))/den; half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return max(0,center-half), min(1,center+half)

def precision_sample_size(expected_precision:float, half_width:float, z:float=1.959963984540054):
    if not (0<expected_precision<1 and 0<half_width<1): raise ValueError('invalid inputs')
    return math.ceil(z*z*expected_precision*(1-expected_precision)/(half_width*half_width))

def clustered_bootstrap_difference(df:pd.DataFrame, metric_col:str, group_col:str, arm_col:str, arm_a:str, arm_b:str, n_boot:int=2000, seed:int=20260807):
    groups=df[group_col].dropna().unique()
    if len(groups)<2: raise ValueError('need at least two clusters')
    rng=np.random.default_rng(seed); vals=[]
    for _ in range(n_boot):
        sampled=rng.choice(groups,size=len(groups),replace=True)
        parts=[df[df[group_col]==g] for g in sampled]; x=pd.concat(parts,ignore_index=True)
        a=pd.to_numeric(x.loc[x[arm_col]==arm_a,metric_col],errors='coerce').dropna(); b=pd.to_numeric(x.loc[x[arm_col]==arm_b,metric_col],errors='coerce').dropna()
        if len(a) and len(b): vals.append(float(a.mean()-b.mean()))
    if not vals: return {'estimate':None,'ci95':(None,None)}
    aa=pd.to_numeric(df.loc[df[arm_col]==arm_a,metric_col],errors='coerce').dropna(); bb=pd.to_numeric(df.loc[df[arm_col]==arm_b,metric_col],errors='coerce').dropna()
    return {'estimate':float(aa.mean()-bb.mean()),'ci95':(float(np.quantile(vals,.025)),float(np.quantile(vals,.975))),'bootstrap_samples':len(vals)}

def ipcw_weights(event_observed, censoring_survival):
    e=np.asarray(event_observed,dtype=float); g=np.asarray(censoring_survival,dtype=float)
    if np.any(g<=0) or len(e)!=len(g): raise ValueError('invalid censoring survival')
    return e/g


def kaplan_meier_censoring_survival(times, event_observed):
    """Estimate G(t)=P(C>=t), treating non-event observations as censoring events.

    Returns a vector evaluated immediately before each subject's observed time,
    suitable for simple IPCW outcome summaries. For publication analyses, the
    manuscript additionally requires cluster-aware/bootstrap uncertainty.
    """
    t=np.asarray(times,dtype=float); e=np.asarray(event_observed,dtype=int)
    if len(t)!=len(e) or len(t)==0 or np.any(t<0): raise ValueError('invalid times/events')
    # censor-event indicator: 1 when the outcome was not observed by the end of follow-up
    c=1-e
    uniq=np.sort(np.unique(t)); g=1.0; g_before={}
    for u in uniq:
        g_before[u]=g
        risk=np.sum(t>=u); d=np.sum((t==u)&(c==1))
        if risk>0: g*=max(0.0,1-d/risk)
    return np.asarray([max(g_before[x],1e-12) for x in t],dtype=float)


def landmark_outcomes(df:pd.DataFrame, followup_days_col:str='followup_days', event_col:str='event_observed', horizons=(30,90,180,365)):
    """Censor-aware event summaries at fixed, preregistered horizons."""
    if followup_days_col not in df or event_col not in df: raise ValueError('missing follow-up columns')
    t=pd.to_numeric(df[followup_days_col],errors='coerce').to_numpy(float); e=pd.to_numeric(df[event_col],errors='coerce').fillna(0).to_numpy(int)
    valid=np.isfinite(t); t=t[valid]; e=e[valid]
    if not len(t): return []
    rows=[]
    for h in horizons:
        # Observed event by h. Subjects censored before h do not enter the naive denominator.
        observed=((e==1)&(t<=h)); known=((e==1)&(t<=h)) | (t>=h)
        naive=float(observed[known].mean()) if known.any() else None
        rows.append({'horizon_days':int(h),'n_total':int(len(t)),'n_known_at_horizon':int(known.sum()),'events_by_horizon':int(observed.sum()),'naive_risk_among_known':naive,'censored_before_horizon':int(((e==0)&(t<h)).sum())})
    return rows


def ipcw_binary_metric(y_true, y_score, followup_days, event_observed, horizon_days:float, threshold:float=0.5):
    """Compute a simple IPCW precision/recall panel for a fixed prediction horizon.

    Cases with observed events before the horizon and cases followed through the
    horizon are evaluable; earlier-censored cases are excluded from the point
    estimate. Censoring weights are estimated nonparametrically from the cohort.
    """
    y=np.asarray(y_true,dtype=int); s=np.asarray(y_score,dtype=float); t=np.asarray(followup_days,dtype=float); e=np.asarray(event_observed,dtype=int)
    if not (len(y)==len(s)==len(t)==len(e)): raise ValueError('length mismatch')
    g=kaplan_meier_censoring_survival(t,e)
    evaluable=((e==1)&(t<=horizon_days)) | (t>=horizon_days)
    target=((e==1)&(t<=horizon_days)).astype(int)
    pred=(s>=threshold).astype(int)
    w=np.where(evaluable,1.0/g,0.0)
    tp=float(np.sum(w*(pred==1)*(target==1))); fp=float(np.sum(w*(pred==1)*(target==0))); fn=float(np.sum(w*(pred==0)*(target==1)))
    precision=tp/(tp+fp) if tp+fp else None; recall=tp/(tp+fn) if tp+fn else None
    return {'horizon_days':float(horizon_days),'threshold':float(threshold),'evaluable':int(evaluable.sum()),'ipcw_precision':precision,'ipcw_recall':recall,'weighted_tp':tp,'weighted_fp':fp,'weighted_fn':fn}


def censoring_sensitivity_bounds(events_observed:int, censored_before_horizon:int, known_non_events:int):
    """Worst/best-case risk bounds when early-censored outcomes are unidentified."""
    n=events_observed+censored_before_horizon+known_non_events
    if n<=0: return (None,None)
    return events_observed/n, (events_observed+censored_before_horizon)/n
