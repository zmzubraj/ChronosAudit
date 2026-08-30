from chronosaudit_stage2.onchain import ProviderObservation
from chronosaudit_stage2.deployment_stream import (
    canonical_creation_set,
    collect_block_deployments,
    creations_from_geth_calltracer,
    creations_from_parity_traces,
    provider_capability_probe,
    trace_transaction_backend,
)

BH='0x'+'aa'*32
TX='0x'+'bb'*32
ADDR='0x'+'22'*20
CREATOR='0x'+'11'*20

class TraceProvider:
    def __init__(self,pid,family,backend='parity'):
        self.provider_id=pid; self.provider_family=family; self.backend=backend
    def call(self,method,params):
        if method=='eth_getBlockByNumber':
            full = bool(params[1]) if len(params)>1 else False
            result={'hash':BH,'number':'0xa','transactions':[{'hash':TX,'to':CREATOR,'from':CREATOR}] if full else []}
            return ProviderObservation(self.provider_id,method,params,result,1,None,'h1')
        if method=='eth_getTransactionReceipt':
            return ProviderObservation(self.provider_id,method,params,{'transactionHash':TX,'contractAddress':None},1,None,'h2')
        if method=='trace_transaction' and self.backend=='parity':
            tr=[{'type':'create','transactionHash':TX,'traceAddress':[0],'action':{'from':CREATOR,'creationMethod':'create2'},'result':{'address':ADDR}}]
            return ProviderObservation(self.provider_id,method,params,tr,1,None,'ht1')
        if method=='trace_transaction':
            return ProviderObservation(self.provider_id,method,params,None,1,'unsupported',None)
        if method=='debug_traceTransaction' and self.backend=='geth':
            row={'type':'CALL','calls':[{'type':'CREATE2','from':CREATOR,'to':ADDR}]}
            return ProviderObservation(self.provider_id,method,params,row,1,None,'ht2')
        if method=='debug_traceTransaction':
            return ProviderObservation(self.provider_id,method,params,None,1,'unsupported',None)
        if method=='trace_block' and self.backend=='parity':
            tr=[{'type':'create','transactionHash':TX,'traceAddress':[0],'action':{'from':CREATOR,'creationMethod':'create2'},'result':{'address':ADDR}}]
            return ProviderObservation(self.provider_id,method,params,tr,1,None,'h3')
        if method=='trace_block':
            return ProviderObservation(self.provider_id,method,params,None,1,'unsupported',None)
        if method=='debug_traceBlockByNumber' and self.backend=='geth':
            rows=[{'txHash':TX,'result':{'type':'CALL','calls':[{'type':'CREATE2','from':CREATOR,'to':ADDR}]}}]
            return ProviderObservation(self.provider_id,method,params,rows,1,None,'h4')
        if method=='debug_traceBlockByNumber':
            return ProviderObservation(self.provider_id,method,params,None,1,'unsupported',None)
        return ProviderObservation(self.provider_id,method,params,None,1,'unknown',None)

def test_capability_probe_accepts_multiple_trace_backends():
    r=provider_capability_probe([TraceProvider('a','quicknode','parity'),TraceProvider('b','chainstack','geth')],10)
    assert r['archive_ready_count']==2 and r['trace_ready_count']==2
    assert r['independent_verified_provider_families']==2

def test_collect_block_deployments_cross_backend_consensus():
    r=collect_block_deployments('ethereum',10,[TraceProvider('a','quicknode','parity'),TraceProvider('b','chainstack','geth')])
    assert r['status']=='complete'
    assert r['independent_verified_provider_families']==2
    assert len(r['records'])==1 and r['records'][0]['creation_type']=='internal_create2'


def test_transaction_trace_backends_normalize_to_same_creation_set():
    parity = creations_from_parity_traces(
        'ethereum',
        10,
        BH,
        [{
            'type':'create',
            'transactionHash':TX,
            'traceAddress':[0],
            'action':{'from':CREATOR,'creationMethod':'create2'},
            'result':{'address':ADDR},
        }],
    )
    geth = creations_from_geth_calltracer(
        'ethereum',
        10,
        BH,
        [{'txHash':TX,'result':{'type':'CALL','calls':[
            {'type':'CREATE2','from':CREATOR,'to':ADDR},
        ]}}],
    )
    assert canonical_creation_set(parity) == canonical_creation_set(geth)


def test_trace_backend_prefers_transaction_scope():
    method, rows, response_sha256, error = trace_transaction_backend(
        TraceProvider('a','quicknode','parity'),
        TX,
    )
    assert method == 'trace_transaction'
    assert rows
    assert response_sha256 == 'ht1'
    assert error is None


def test_trace_backend_falls_back_to_geth_transaction_calltracer():
    method, rows, response_sha256, error = trace_transaction_backend(
        TraceProvider('b','chainstack','geth'),
        TX,
    )
    assert method == 'debug_traceTransaction_callTracer'
    assert rows['calls'][0]['to'] == ADDR
    assert response_sha256 == 'ht2'
    assert error is None


def test_geth_calltracer_recurses_and_hashes_deterministically():
    rows = [{'txHash':TX,'result':{'type':'CALL','calls':[
        {'type':'CALL','calls':[{'type':'CREATE','from':CREATOR,'to':ADDR}]},
    ]}}]
    first = creations_from_geth_calltracer('ethereum',10,BH,rows)
    second = creations_from_geth_calltracer('ethereum',10,BH,rows)
    assert first == second
    assert first[0].trace_address == '[0,0]'
    assert first[0].creation_type == 'internal_create'


def test_collect_block_deployments_requires_candidate_presence_when_bound():
    result = collect_block_deployments(
        'ethereum',
        10,
        [TraceProvider('a','quicknode','parity'),TraceProvider('b','chainstack','geth')],
        candidate_address='0x'+'99'*20,
    )
    assert result['status'] == 'blocked_candidate_missing'


def test_collect_block_deployments_rejects_same_family_agreement():
    result = collect_block_deployments(
        'ethereum',
        10,
        [TraceProvider('a','shared-family','parity'),TraceProvider('b','shared-family','geth')],
        candidate_address=ADDR,
    )
    assert result['status'] == 'blocked_trace_disagreement'
