import chronosaudit_stage2.source_history as sh

def test_sourcify_adapter_parses_verified_at(monkeypatch):
    payload={'match':'exact_match','verifiedAt':'2024-01-01T00:00:00Z','compilerVersion':'0.8.20','sources':{'A.sol':{'content':'contract A{}'}}}
    monkeypatch.setattr(sh,'_fetch_json',lambda url,timeout:(payload,'f'*64))
    o=sh.sourcify_contract_observation('ethereum','0x'+'11'*20)
    assert o.status=='verified' and o.verified_at.startswith('2024-01-01') and o.exact_match is True and o.source_sha256

def test_etherscan_source_and_creation_adapters(monkeypatch):
    source={'result':[{'SourceCode':'contract A{}','CompilerVersion':'v0.8.20'}]}
    creation={'result':[{'contractCreator':'0x'+'22'*20,'txHash':'0x'+'33'*32,'blockNumber':'123','timestamp':'1700000000','creationBytecode':'0x6000'}]}
    calls=[]
    def fake(url,timeout):
        calls.append(url)
        return (creation if 'getcontractcreation' in url else source,'e'*64)
    monkeypatch.setattr(sh,'_fetch_json',fake)
    s=sh.etherscan_source_observation('ethereum','0x'+'11'*20,api_key='x')
    d=sh.etherscan_deployment_observation('ethereum','0x'+'11'*20,api_key='x')
    assert s.status=='verified' and s.source_sha256
    assert d.status=='located' and d.deployment_block==123 and d.creation_tx_hash.startswith('0x33')
