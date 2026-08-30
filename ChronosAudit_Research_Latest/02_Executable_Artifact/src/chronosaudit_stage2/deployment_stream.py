from __future__ import annotations
import hashlib, json
from dataclasses import dataclass, asdict
from typing import Any, Iterable
from .onchain import JsonRpcProvider, block_tag, provider_consensus, normalize_block_header

@dataclass(frozen=True)
class DeploymentRecord:
    chain: str; block_number: int; block_hash: str; transaction_hash: str; contract_address: str
    creator_address: str | None; creation_type: str; trace_address: str; evidence_sha256: str

CreationKey = tuple[str, str, str, str | None, str]

def _hash_payload(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def canonical_creation_set(records: Iterable[DeploymentRecord]) -> tuple[CreationKey, ...]:
    return tuple(sorted({
        (
            row.transaction_hash,
            row.contract_address,
            row.creation_type,
            row.creator_address,
            row.trace_address,
        )
        for row in records
    }))

def top_level_creations_from_block(chain, block, receipts):
    by_tx={str(r.get('transactionHash','')).lower():r for r in receipts}; out=[]
    number=int(block['number'],16); bh=str(block['hash']).lower()
    for tx in block.get('transactions',[]):
        if tx.get('to') is not None: continue
        th=str(tx.get('hash','')).lower(); rec=by_tx.get(th,{}); addr=rec.get('contractAddress')
        if not addr: continue
        ev={'block':bh,'tx':th,'receipt_contract':addr,'from':tx.get('from')}
        out.append(DeploymentRecord(chain,number,bh,th,str(addr).lower(),(tx.get('from') or '').lower() or None,'top_level_create','[]',_hash_payload(ev)))
    return out

def creations_from_parity_traces(chain, block_number, block_hash, traces):
    out=[]
    for tr in traces:
        if str(tr.get('type','')).lower()!='create': continue
        action=tr.get('action') or {}; result=tr.get('result') or {}; addr=result.get('address'); th=tr.get('transactionHash')
        if not addr or not th: continue
        ctype='internal_create2' if str(action.get('creationMethod','')).lower()=='create2' else 'internal_create'
        ta=json.dumps(tr.get('traceAddress') or [],separators=(',',':'))
        out.append(DeploymentRecord(chain,block_number,block_hash.lower(),str(th).lower(),str(addr).lower(),(action.get('from') or '').lower() or None,ctype,ta,_hash_payload({'block':block_hash,'tx':th,'trace':tr})))
    return out

def _walk_calltracer(node, path=()):
    yield node, path
    for i,ch in enumerate(node.get('calls') or []): yield from _walk_calltracer(ch, path+(i,))

def creations_from_geth_calltracer(chain, block_number, block_hash, rows):
    out=[]
    for row in rows or []:
        th=row.get('txHash') or row.get('transactionHash'); root=row.get('result') if isinstance(row.get('result'),dict) else row
        if not th or not isinstance(root,dict): continue
        for node,path in _walk_calltracer(root):
            typ=str(node.get('type','')).upper()
            if typ not in {'CREATE','CREATE2'}: continue
            addr=node.get('to') or node.get('address')
            if not addr: continue
            ta=json.dumps(list(path),separators=(',',':')); ctype='internal_create2' if typ=='CREATE2' else 'internal_create'
            out.append(DeploymentRecord(chain,block_number,block_hash.lower(),str(th).lower(),str(addr).lower(),(node.get('from') or '').lower() or None,ctype,ta,_hash_payload({'block':block_hash,'tx':th,'call':node,'path':path})))
    return out

def trace_backend(provider, tag):
    p=provider.call('trace_block',[tag])
    if p.error is None and isinstance(p.result,list): return 'trace_block', p.result, p.response_sha256, None
    g=provider.call('debug_traceBlockByNumber',[tag,{'tracer':'callTracer','timeout':'120s'}])
    if g.error is None and isinstance(g.result,list): return 'debug_traceBlockByNumber_callTracer', g.result, g.response_sha256, None
    return None, None, None, {'trace_block':p.error,'debug_traceBlockByNumber':g.error}

def trace_transaction_backend(provider, transaction_hash):
    parity=provider.call('trace_transaction',[transaction_hash])
    if parity.error is None and isinstance(parity.result,list):
        return 'trace_transaction', parity.result, parity.response_sha256, None
    geth=provider.call('debug_traceTransaction',[transaction_hash,{'tracer':'callTracer','timeout':'120s'}])
    if geth.error is None and isinstance(geth.result,dict):
        return 'debug_traceTransaction_callTracer', geth.result, geth.response_sha256, None
    return None, None, None, {
        'trace_transaction':parity.error,
        'debug_traceTransaction':geth.error,
    }

def provider_capability_probe(providers, historical_block):
    tag=block_tag(historical_block); rows=[]
    for provider in providers:
        block=provider.call('eth_getBlockByNumber',[tag,False]); backend,_,thash,terr=trace_backend(provider,tag)
        rows.append({'provider_id':provider.provider_id,'provider_family':getattr(provider,'provider_family','unverified'),'historical_block_ok':block.error is None and isinstance(block.result,dict) and bool(block.result.get('hash')),'trace_backend':backend,'trace_ok':backend is not None,'block_response_sha256':block.response_sha256,'trace_response_sha256':thash,'trace_errors':terr})
    fam={r['provider_family'] for r in rows if r['historical_block_ok'] and r['provider_family']!='unverified'}
    return {'historical_block':historical_block,'providers':rows,'archive_ready_count':sum(r['historical_block_ok'] for r in rows),'trace_ready_count':sum(r['trace_ok'] for r in rows),'independent_verified_provider_families':len(fam)}

def collect_block_deployments(chain, block_number, providers, candidate_address=None):
    if len(providers)<2: return {'status':'blocked_requires_two_providers','records':[]}
    tag=block_tag(block_number); cons=provider_consensus(providers,'eth_getBlockByNumber',[tag,True],normalize_block_header)
    if cons['status']!='consensus': return {'status':'blocked_block_consensus','block':cons,'records':[]}
    bh=cons['value']['hash']; provider_rows=[]; per_provider=[]
    for provider in providers:
        b=provider.call('eth_getBlockByNumber',[tag,True])
        if b.error or not isinstance(b.result,dict) or str(b.result.get('hash','')).lower()!=bh.lower():
            provider_rows.append({'provider_id':provider.provider_id,'status':'block_mismatch_or_error','error':b.error}); continue
        receipts=[]
        for tx in b.result.get('transactions') or []:
            if tx.get('hash'):
                r=provider.call('eth_getTransactionReceipt',[tx['hash']])
                if r.error is None and isinstance(r.result,dict): receipts.append(r.result)
        top=top_level_creations_from_block(chain,b.result,receipts)
        backend,traces,thash,terr=trace_backend(provider,tag); internal=[]
        if backend=='trace_block': internal=creations_from_parity_traces(chain,block_number,bh,traces)
        elif backend=='debug_traceBlockByNumber_callTracer': internal=creations_from_geth_calltracer(chain,block_number,bh,traces)
        recs=top+internal; keys=canonical_creation_set(recs); per_provider.append((provider,keys,recs,backend))
        provider_rows.append({'provider_id':provider.provider_id,'provider_family':getattr(provider,'provider_family','unverified'),'status':'ok','top_level':len(top),'internal':len(internal),'trace_backend':backend,'trace_response_sha256':thash,'trace_errors':terr})
    trace_sets=[x for x in per_provider if x[3] is not None]
    families={getattr(p,'provider_family','unverified') for p,_,_,_ in trace_sets if getattr(p,'provider_family','unverified')!='unverified'}
    agreement=False; agreed_records=[]
    for i in range(len(trace_sets)):
        for j in range(i+1,len(trace_sets)):
            left_family=getattr(trace_sets[i][0],'provider_family','unverified')
            right_family=getattr(trace_sets[j][0],'provider_family','unverified')
            if left_family=='unverified' or left_family==right_family:
                continue
            if trace_sets[i][1]==trace_sets[j][1]: agreement=True; agreed_records=trace_sets[i][2]; break
        if agreement: break
    if len(trace_sets)<2: status='partial_missing_independent_internal_create_trace'
    elif not agreement: status='blocked_trace_disagreement'
    elif len(families)<2: status='blocked_provider_family_independence_unverified'
    elif candidate_address is not None and str(candidate_address).lower() not in {
        row.contract_address for row in agreed_records
    }: status='blocked_candidate_missing'
    else: status='complete'
    return {'status':status,'block_number':block_number,'block_hash':bh,'trace_provider_count':len(trace_sets),'independent_verified_provider_families':len(families),'providers':provider_rows,'records':[asdict(r) for r in sorted(agreed_records,key=lambda r:(r.transaction_hash,r.trace_address,r.contract_address))]}
