from __future__ import annotations

import argparse, csv, hashlib, json, socket, sys, time, urllib.error, urllib.request
from pathlib import Path
import pandas as pd

ROOT=Path(__file__).resolve().parent
PUBLIC={
 'ethereum': [('publicnode','https://ethereum-rpc.publicnode.com'),('1rpc','https://public.1rpc.io/eth')],
 'bsc': [('publicnode','https://bsc-rpc.publicnode.com'),('1rpc','https://public.1rpc.io/bnb')],
 'base': [('publicnode','https://base-rpc.publicnode.com'),('1rpc','https://public.1rpc.io/base')],
 'arbitrum': [('publicnode','https://arbitrum-one-rpc.publicnode.com'),('1rpc','https://public.1rpc.io/arb')],
}

def rpc(url, method, params, timeout=15):
    raw=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
    req=urllib.request.Request(url,data=raw,headers={'Content-Type':'application/json','User-Agent':'ChronosAudit-PublicArchiveProbe/1.0'})
    with urllib.request.urlopen(req,timeout=timeout) as r: body=r.read()
    return json.loads(body), hashlib.sha256(body).hexdigest()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--execute',action='store_true'); ap.add_argument('--limit',type=int,default=0); ap.add_argument('--timeout',type=int,default=15); args=ap.parse_args()
    cases=pd.read_csv(ROOT/'raw'/'scone_bench.csv'); cases['chain']=cases.chain.replace({'mainnet':'ethereum','arbi':'arbitrum'})
    if args.limit: cases=cases.head(args.limit)
    plan=[]
    for _,r in cases.iterrows():
        chain=str(r.chain); address=str(r.target_contract_address); block=int(r.fork_block_number); blocktag=hex(block)
        for family,url in PUBLIC[chain]:
            plan.append({'case_name':r.case_name,'chain':chain,'address':address,'historical_anchor_block':block,'provider_family':family,'provider_url':url,'method':'eth_getCode','params':json.dumps([address,blocktag])})
    plan_path=ROOT/'external'/'dual_provider_417_probe_plan.csv'; plan_path.parent.mkdir(exist_ok=True); pd.DataFrame(plan).to_csv(plan_path,index=False)
    result={'cases':len(cases),'planned_observations':len(plan),'provider_families_per_chain':2,'mode':'execute' if args.execute else 'plan_only','plan_sha256':hashlib.sha256(plan_path.read_bytes()).hexdigest()}
    if not args.execute:
        print(json.dumps(result,indent=2)); return
    rows=[]
    for x in plan:
        rec=dict(x); started=time.time()
        try:
            payload,ph=rpc(x['provider_url'],x['method'],json.loads(x['params']),args.timeout)
            code=payload.get('result') if isinstance(payload,dict) else None
            rec.update(status='ok' if isinstance(code,str) else 'rpc_error',result_sha256=hashlib.sha256((code or '').encode()).hexdigest() if isinstance(code,str) else '',payload_sha256=ph,error='' if isinstance(code,str) else json.dumps(payload)[:500])
        except Exception as e:
            rec.update(status='environment_or_provider_error',result_sha256='',payload_sha256='',error=f'{type(e).__name__}: {e}')
        rec['elapsed_seconds']=round(time.time()-started,3); rows.append(rec)
    out=ROOT/'external'/'dual_provider_417_probe_results.csv'; pd.DataFrame(rows).to_csv(out,index=False)
    ok=pd.DataFrame(rows); result.update(executed=len(rows),ok=int((ok.status=='ok').sum()),output_sha256=hashlib.sha256(out.read_bytes()).hexdigest())
    print(json.dumps(result,indent=2))
if __name__=='__main__': main()
